# Explicación técnica del software de intercambio de llaves

## 1. Objetivo del reto

El software implementa un flujo simplificado de intercambio seguro de llaves usado en entornos de pagos:

1. Recibe dos componentes independientes de una KEK.
2. Recombinarlos mediante XOR para obtener la KEK.
3. Verifica que la KEK sea correcta usando su KCV.
4. Usa la KEK para desenvolver una BDK protegida dentro de un bloque TR-31.
5. Verifica el KCV de la BDK.
6. Usa la BDK en el bonus DUKPT para derivar una clave transaccional.
7. Descifra el mensaje de prueba `MELI_Rocks!`.
8. En el flujo de exportación, genera una PEK aleatoria y la protege con TR-31.

La lógica criptográfica está en `key_exchange/crypto_utils.py`, el bonus DUKPT en `key_exchange/bonus.py`, la interfaz gráfica en `key_exchange/gui.py` y el modo automatizado en `key_exchange/cli.py`.

---

## 2. Conceptos principales

### 2.1 Claves y componentes

Una clave criptográfica no debería circular necesariamente como un único valor visible. En este reto, la KEK se entrega dividida en dos componentes:

- Componente 1: `db375bb9dce3b14947e04e92a9356ebbb6e456f3518aed92c8dbc891f22f55d6`
- Componente 2: `1e924acdb5442d3000c0fc9b20101aff1bd7a9bc27d36888c50cef64a7c818b7`

Cada componente tiene 64 caracteres hexadecimales, es decir:

- 2 caracteres hexadecimales representan 1 byte.
- 64 caracteres representan 32 bytes.
- 32 bytes representan 256 bits.

La KEK significa **Key Encryption Key**: es una clave usada para proteger o transportar otras claves, no para cifrar directamente los datos de la transacción.

La BDK significa **Base Derivation Key**: es la clave base utilizada por DUKPT para derivar claves transaccionales únicas.

La PEK significa **PIN Encryption Key**: es una clave que puede utilizarse para proteger datos relacionados con PIN, según el uso asignado en el key block.

---

## 3. Obtención matemática de la KEK

### 3.1 Conversión hexadecimal a bytes

El software recibe los componentes como texto hexadecimal. La operación:

```python
bytes.fromhex(comp1_hex)
```

convierte cada pareja de caracteres hexadecimales en un byte.

Por ejemplo:

```text
"AF" -> 0xAF -> 175
```

Después de convertir ambos componentes, el programa confirma que tengan la misma longitud. No es válido aplicar XOR entre cadenas de tamaños diferentes.

### 3.2 XOR componente a componente

La KEK se obtiene con XOR exclusivo byte por byte:

$$
KEK = C_1 \oplus C_2
$$

Para cada posición $i$:

$$
KEK_i = C_{1,i} \oplus C_{2,i}
$$

Las propiedades importantes de XOR son:

$$
A \oplus 0 = A
$$

$$
A \oplus A = 0
$$

$$
(A \oplus B) \oplus B = A
$$

Con los componentes del reto, el resultado es:

```text
C5A5117469A79C794720B20989257444AD33FF4F7659851A0DD727F555E74D61
```

Esta es la KEK de 32 bytes que se utiliza en la protección TR-31.

### 3.3 Importancia de split knowledge

La división busca que ninguna persona o canal individual conozca la KEK completa. En un entorno real, cada componente debería ser administrado por custodios, procesos o canales independientes.

El XOR no hace que un componente sea mágicamente secreto si el otro componente queda expuesto. Si un atacante obtiene ambos valores, puede calcular la KEK inmediatamente. La seguridad depende de mantener separadas las responsabilidades y los componentes.

---

## 4. Validación de la KEK mediante KCV

### 4.1 Qué es un KCV

KCV significa **Key Check Value**. Es un valor corto derivado de una clave para detectar errores de captura, transporte o combinación.

Un KCV no es la clave y no debe considerarse una prueba de autenticación fuerte. En este proyecto se usan los primeros 3 bytes del resultado criptográfico:

```text
3 bytes = 6 caracteres hexadecimales
```

El KCV esperado de la KEK es:

```text
F74B90
```

### 4.2 KCV para claves TDES

La KEK calculada tiene 32 bytes, pero el bloque TR-31 utilizado por `psec` permite usarla como clave de protección AES. Para el cálculo de KCV del proyecto, las claves de 16 o 24 bytes se validan mediante TDES sobre un bloque cero de 8 bytes.

Conceptualmente:

$$
KCV_{TDES} = \operatorname{Trunc}_3\left(\operatorname{3DES}_{K}(0^8)\right)
$$

Para una clave AES-256, la función del proyecto usa CMAC-AES:

$$
KCV_{AES} = \operatorname{Trunc}_3\left(\operatorname{CMAC}_{AES_K}(0^{16})\right)
$$

El algoritmo del KCV debe coincidir con la familia de la clave. Aplicar AES-CMAC a una clave TDES o aplicar TDES a una clave AES cambia el resultado y produce una validación incorrecta.

### 4.3 Validación implementada

La función `validate_cmac_kcv` calcula el KCV y lo compara con el esperado:

```python
if kcv != expected_kcv.upper():
    raise ValueError(...)
```

Si el valor no coincide, el flujo se detiene antes de intentar desenvolver la clave.

---

## 5. Bloque TR-31 de la BDK

### 5.1 Qué es TR-31

TR-31 es un formato de key block para transportar claves criptográficas protegidas. Un key block combina:

- Un encabezado con metadatos.
- Material criptográfico protegido.
- Un valor de autenticación que permite detectar manipulación.

El software no descifra el texto TR-31 mediante operaciones manuales. Utiliza:

```python
from psec.tr31 import KeyBlock
```

Esto es importante porque el formato tiene reglas específicas de encabezado, longitud, padding, cifrado y autenticación.

### 5.2 Key block de referencia

El key block BDK del reto es:

```text
D0112B0TX00E000080BF1D76A239777F8C2B605EB4FCF6DC9B9CFC6A5170C18282BDAB7D4D4D4559BC6A952101BA74EF8C1563BC2A73BF76
```

Su encabezado comienza con:

```text
D0112B0T...
```

El uso `B0` identifica el propósito de la clave como una clave base DUKPT en el contexto del reto.

La clave se desenvuelve con:

```python
kb = KeyBlock(kbpk=kek)
bdk = kb.unwrap(tr31_string)
```

Aquí `kbpk` significa **Key Block Protection Key**, que en este ejercicio es la KEK.

### 5.3 Resultado de la desenvoltura

Después de validar la KEK y desenvolver el bloque, la BDK obtenida es:

```text
39EDE3A9437F3FF561898D1F6FABBD25
```

Esta BDK tiene 16 bytes, por lo que se usa como clave TDES de dos llaves dentro del flujo DUKPT.

El KCV esperado de la BDK es:

```text
EABBDC
```

El software no continúa al bonus hasta que este valor coincide.

### 5.4 Diferencia entre BDK y PEK

El archivo `pek_tr31.txt` generado por el módulo de exportación contiene una PEK nueva. Su encabezado normalmente comienza con:

```text
D0144P...
```

La letra `P` indica el uso PEK. Por tanto:

- `D0112B0...` corresponde al key block BDK del reto.
- `D0144P0...` corresponde a un key block PEK generado por la aplicación.

No se debe utilizar `pek_tr31.txt` como si fuera el bloque BDK.

---

## 6. Flujo de exportación de la PEK

El módulo **Exportar PEK** de la GUI ejecuta estas etapas:

### Paso 1: recombinar y validar la KEK

Se convierten los dos componentes a bytes, se aplica XOR y se calcula el KCV de la KEK.

El proceso solo continúa si el KCV coincide con `F74B90`.

### Paso 2: generar la PEK

La aplicación genera 32 bytes aleatorios mediante:

```python
os.urandom(32)
```

Esto representa una PEK AES-256 nueva.

Como la generación es aleatoria, es normal que cambien en cada ejecución:

- La PEK.
- Su KCV.
- El key block TR-31 completo.
- El contenido de `pek_tr31.txt`.

La KEK y la BDK de referencia no cambian.

### Paso 3: envolver la PEK

La PEK se protege con:

```python
wrap_tr31(pek, kek, usage="P")
```

La función crea un encabezado TR-31 para el uso de PIN/PEK y escribe el resultado en el archivo indicado.

---

## 7. Flujo de importación de la BDK

El módulo **Importar BDK** ejecuta exactamente este orden:

### Paso 1: combinar y validar la KEK

$$
KEK = C_1 \oplus C_2
$$

Luego se compara el KCV calculado con `F74B90`.

### Paso 2: desenvolver el key block

La cadena TR-31 se procesa con la KEK. El resultado esperado es:

```text
39EDE3A9437F3FF561898D1F6FABBD25
```

La GUI también rechaza explícitamente un archivo cuyo encabezado comienza con `D0144P`, porque ese valor identifica una PEK y no la BDK requerida.

### Paso 3: validar la BDK

Se calcula el KCV de la BDK y se compara con:

```text
EABBDC
```

### Paso 4: ejecutar DUKPT

La BDK validada se usa para derivar una clave transaccional a partir del KSN del reto.

La GUI muestra cada resultado en una tarjeta visual. El paso DUKPT solo aparece como completado cuando la derivación y el descifrado terminan correctamente.

---

## 8. DUKPT: concepto matemático

### 8.1 Qué significa DUKPT

DUKPT significa **Derived Unique Key Per Transaction**. El objetivo es que cada transacción utilice una clave diferente derivada de:

- Una BDK compartida de forma segura.
- Un KSN asociado al dispositivo.
- Un contador de transacciones.

El sistema no transmite la BDK como clave de trabajo. La BDK sirve como raíz para generar claves derivadas.

### 8.2 KSN del reto

El KSN utilizado es:

```text
729C77361E9A51E000F2
```

El KSN contiene información de identificación y un contador de 21 bits. El contador permite generar una secuencia de claves distintas para un mismo dispositivo.

El contador de 21 bits puede representar valores desde:

$$
0 \quad \text{hasta} \quad 2^{21}-1
$$

Es decir, hasta 2.097.151 posiciones posibles antes de agotar el espacio del contador.

### 8.3 Generación del IPEK

El primer paso DUKPT es generar el IPEK, o **Initial PIN Encryption Key**.

La BDK de 16 bytes se expande a una clave 3DES de 24 bytes:

$$
K_{3DES} = BDK \mathbin{||} BDK[0:8]
$$

donde `||` significa concatenación.

El KSN se prepara poniendo en cero su contador. Después se cifran los primeros 8 bytes del KSN con 3DES:

$$
IPEK_L = 3DES_{K_{3DES}}(KSN_{base}[0:8])
$$

Para obtener la mitad derecha se aplica una máscara conocida:

```text
C0C0C0C000000000C0C0C0C000000000C0C0C0C000000000
```

La clave enmascarada es:

$$
K' = K_{3DES} \oplus Mask
$$

y se calcula:

$$
IPEK_R = 3DES_{K'}(KSN_{base}[0:8])
$$

Finalmente:

$$
IPEK = IPEK_L \mathbin{||} IPEK_R
$$

Para este reto, el IPEK obtenido es:

```text
db833e79b68b868c285534462f0099b5
```

### 8.4 Registro de clave actual

El algoritmo conserva un registro de 16 bytes llamado `curkey`. Inicialmente:

$$
curkey = IPEK
$$

También prepara una versión del KSN sin los bits de contador y examina el contador mediante máscaras de bits.

### 8.5 Procesamiento bit a bit del contador

Se utiliza un registro de selección que empieza en:

```text
000100
```

En cada iteración se desplaza un bit hacia la derecha:

$$
SR_{i+1} = SR_i >> 1
$$

Se calcula una intersección bit a bit entre el registro de selección y el contador:

$$
T = SR \land Counter
$$

Si $T$ no es cero, ese bit del contador debe procesarse.

El contador parcial se actualiza con OR:

$$
R8 = R8 \lor SR
$$

Luego el algoritmo calcula la mitad derecha de la clave derivada mediante una operación tipo ANSI X9.24:

1. Separar la mitad derecha de `curkey`.
2. Aplicar XOR con el registro `R8`.
3. Cifrar el resultado con DES usando la mitad izquierda de `curkey`.
4. Volver a aplicar XOR con la mitad derecha original.

Formalmente, para la primera parte:

$$
R8A = DES_{curkey_L}(R8 \oplus curkey_R) \oplus curkey_R
$$

Después se modifica la clave con la máscara de derivación:

$$
curkey' = curkey \oplus C\_MASK
$$

La máscara de derivación de 16 bytes es:

```text
C0C0C0C000000000C0C0C0C000000000
```

Se repite el proceso con la clave enmascarada:

$$
R8B = DES_{curkey'_L}(R8 \oplus curkey'_R) \oplus curkey'_R
$$

El nuevo registro de clave se forma como:

$$
curkey = R8B \mathbin{||} R8A
$$

Este procedimiento se repite para cada bit activo del contador del KSN.

### 8.6 Clave derivada del reto

Para el BDK y KSN proporcionados, la clave transaccional derivada es:

```text
F0BBF26A9B1D48220ED642709E5C4454
```

La clave tiene 16 bytes y se utiliza como clave TDES de dos llaves.

---

## 9. Descifrado del mensaje del bonus

El ciphertext del reto es:

```text
FCC832A91953151148E86A01BE9420AC
```

Tiene 16 bytes, es decir, dos bloques de 8 bytes. El software usa TDES en modo ECB:

$$
Plaintext = 3DES^{-1}_{K_{DUKPT}}(Ciphertext)
$$

El resultado hexadecimal es:

```text
4D454C495F526F636B73210000000000
```

La conversión a texto produce:

```text
MELI_Rocks!
```

Los bytes finales `00` son padding nulo. Por eso el programa utiliza:

```python
plaintext.rstrip(b"\x00")
```

antes de decodificar UTF-8.

---

## 10. Arquitectura del software

### `key_exchange/crypto_utils.py`

Contiene las primitivas de alto nivel:

- `xor_components`: combina los componentes de KEK.
- `calculate_cmac_kcv`: calcula el KCV según el tamaño y familia de la clave.
- `validate_cmac_kcv`: compara el KCV calculado con el esperado.
- `wrap_tr31`: protege una clave dentro de un key block TR-31.
- `unwrap_tr31`: desenvuelve una clave desde TR-31.
- `generate_aes256_key`: genera una PEK aleatoria de 32 bytes.

### `key_exchange/bonus.py`

Contiene la implementación local DUKPT:

- `LocalDUKPTServer`: genera el IPEK y la clave derivada.
- `decrypt_bonus_dukpt`: deriva la clave y descifra el ciphertext.
- `run_bonus_dukpt`: imprime el resultado del bonus para el CLI.

La implementación local evita la dependencia externa que provocaba errores de longitudes incompatibles en operaciones XOR.

### `key_exchange/cli.py`

Mantiene la ejecución automatizada:

- `export-pek` genera y protege una PEK.
- `import-bdk` valida la KEK, desenvuelve la BDK y ejecuta el bonus.

### `key_exchange/gui.py`

Proporciona dos módulos visuales:

- **Exportar PEK**.
- **Importar BDK**.

Cada módulo muestra el estado de cada paso. La interfaz usa un panel desplazable para evitar que los campos, valores largos y tarjetas de resultado se superpongan.

### `key_exchange/__main__.py`

Decide el modo de ejecución:

- Sin argumentos: abre la GUI.
- Con argumentos: conserva el CLI.

```bash
python -m key_exchange
python -m key_exchange import-bdk ...
```

---

## 11. Ejecución

Desde el directorio `meli_challenge`:

### Interfaz gráfica

```bash
python -m key_exchange
```

### Exportar PEK

```bash
python -m key_exchange export-pek \
  --kek-component-1 db375bb9dce3b14947e04e92a9356ebbb6e456f3518aed92c8dbc891f22f55d6 \
  --kek-component-2 1e924acdb5442d3000c0fc9b20101aff1bd7a9bc27d36888c50cef64a7c818b7 \
  --kek-kcv F74B90 \
  --out pek_tr31.txt
```

### Importar BDK

```bash
python -m key_exchange import-bdk \
  --kek-component-1 db375bb9dce3b14947e04e92a9356ebbb6e456f3518aed92c8dbc891f22f55d6 \
  --kek-component-2 1e924acdb5442d3000c0fc9b20101aff1bd7a9bc27d36888c50cef64a7c818b7 \
  --kek-kcv F74B90 \
  --bdk-keyblock D0112B0TX00E000080BF1D76A239777F8C2B605EB4FCF6DC9B9CFC6A5170C18282BDAB7D4D4D4559BC6A952101BA74EF8C1563BC2A73BF76 \
  --bdk-kcv EABBDC
```

---

## 12. Resultados esperados

Si se utilizan los valores de referencia correctos:

```text
KEK KCV: F74B90
BDK: 39EDE3A9437F3FF561898D1F6FABBD25
BDK KCV: EABBDC
DUKPT key: F0BBF26A9B1D48220ED642709E5C4454
Mensaje: MELI_Rocks!
```

En la exportación, la PEK y su KCV serán diferentes cada vez. Eso es correcto porque la PEK se genera aleatoriamente.

---

## 13. Consideraciones de seguridad

Este proyecto es educativo y reproduce el flujo del reto. Para un sistema de producción se deberían considerar, como mínimo:

- Usar un HSM para generar, importar y custodiar claves.
- No mostrar claves en claro en la interfaz ni en logs.
- No guardar bloques de claves generados en ubicaciones sin protección.
- Proteger los componentes de KEK con split knowledge y dual control.
- Validar y registrar eventos sin imprimir material secreto.
- Usar versiones actuales y compatibles de las bibliotecas criptográficas.
- Evitar ECB para nuevos diseños; aquí se utiliza porque forma parte del algoritmo y los vectores del reto.
- Rotar y destruir claves según una política formal de ciclo de vida.

La GUI muestra valores de referencia porque este es un ejercicio controlado. En un sistema real, esos valores deberían permanecer protegidos y gestionarse mediante una infraestructura de claves adecuada.
