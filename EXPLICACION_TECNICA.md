# Guía del reto: conceptos, cálculos y recorrido del software

Esta guía está dividida en dos partes:

1. **Conceptos y ejemplos del reto:** qué significa cada valor, de dónde viene y cómo se calcula.
2. **Código e interfaz gráfica:** qué hace cada módulo y en qué paso de la pantalla ocurre.

> Los valores de claves que aparecen aquí pertenecen al ejercicio. En sistemas reales, las claves no deberían mostrarse en una GUI, guardarse en texto plano ni compartirse en documentación.

# Parte 1. Conceptos y ejemplos del reto

## 1. El reto en pocas palabras

El software recibe piezas y datos de una operación de pagos. Debe recomponer una clave de protección, comprobarla, abrir un paquete que contiene otra clave, volver a comprobarla y usarla para descifrar un mensaje de prueba.

El recorrido principal es:

```text
dos componentes -> KEK -> comprobar KEK -> abrir TR-31 -> BDK
BDK -> comprobar BDK -> derivar clave DUKPT -> descifrar mensaje
```

Cada flecha es una operación criptográfica concreta. Si una comprobación falla, el programa se detiene para no continuar con una clave incorrecta.

## 2. Diccionario de términos

| Término | Significado sencillo | Función en este reto |
|---|---|---|
| Clave | Valor secreto usado por un algoritmo criptográfico | Protege o transforma otros datos |
| KEK | *Key Encryption Key* | Protege el transporte de otras claves |
| KCV | *Key Check Value* | Huella corta para detectar errores al copiar o reconstruir una clave |
| TR-31 | Formato estandarizado de bloque de claves | Transporta una clave protegida junto con metadatos y controles de integridad |
| BDK | *Base Derivation Key* | Raíz usada por DUKPT para calcular claves de transacción |
| KSN | *Key Serial Number* | Identifica el dispositivo/secuencia y contiene el contador DUKPT |
| IPEK | *Initial PIN Encryption Key* | Clave inicial calculada desde BDK y KSN base |
| DUKPT | *Derived Unique Key Per Transaction* | Esquema para derivar una clave distinta según el KSN de cada transacción |
| Ciphertext | Texto cifrado | Los bytes que el bonus pide descifrar |
| PEK | *PIN Encryption Key* | Clave que el módulo de exportación crea y protege en TR-31 |

## 3. Entradas del reto y de dónde salen

La GUI carga por defecto estos datos de referencia. En un ejercicio, los valores “entregados” son las entradas del problema; otros valores, como la KEK y la BDK en claro, son resultados calculados al ejecutar el flujo.

| Valor | ¿Entregado o calculado? | Uso |
|---|---|---|
| Componente 1 (`C1`) | Entregado | Primera pieza para reconstruir la KEK |
| Componente 2 (`C2`) | Entregado | Segunda pieza para reconstruir la KEK |
| `F74B90` | Entregado como KCV esperado | Comprobación de la KEK reconstruida |
| Key block `D0112B0T...` | Entregado | Bloque TR-31 que contiene la BDK protegida |
| `EABBDC` | Entregado como KCV esperado | Comprobación de la BDK extraída |
| KSN `729C77361E9A51E000F2` | Entregado en el bonus/código | Parámetro de la derivación DUKPT |
| Ciphertext `FCC832A91953151148E86A01BE9420AC` | Entregado en el bonus/código | Mensaje cifrado que hay que recuperar |
| KEK, BDK, IPEK y clave DUKPT | Calculados | Resultados intermedios del flujo |
| `MELI_Rocks!` | Resultado esperado | Texto recuperado al descifrar el ciphertext |

> **Distinción importante:** `F74B90` y `EABBDC` son referencias que el reto proporciona para comparar. El programa calcula los KCV a partir de las claves y comprueba si coinciden; no calcula esas claves a partir del KCV.

## 4. Paso 1: reconstruir la KEK con XOR

Los dos componentes entregados son:

```text
C1 = db375bb9dce3b14947e04e92a9356ebbb6e456f3518aed92c8dbc891f22f55d6
C2 = 1e924acdb5442d3000c0fc9b20101aff1bd7a9bc27d36888c50cef64a7c818b7
```

Cada pareja de caracteres hexadecimales es un byte. Por ejemplo, los primeros bytes son `DB` y `1E`. El programa aplica XOR por posición:

$$
KEK_i = C1_i \oplus C2_i
$$

Ejemplo del primer byte, en binario:

```text
DB = 11011011
1E = 00011110
     -------- XOR
C5 = 11000101
```

Por eso el primer byte de la KEK calculada es `C5`. La operación se repite para los 32 bytes. La clave completa resultante es:

```text
KEK = C5A5117469A79C794720B20989257444AD33FF4F7659851A0DD727F555E74D61
```

Los dos componentes tienen 64 caracteres hexadecimales, es decir, 32 bytes o 256 bits cada uno. La KEK resultante también mide 32 bytes, por lo que en este programa se trata como AES-256 al calcular su KCV.

### ¿Por qué se usa XOR?

XOR combina bits con estas reglas: iguales producen `0`, distintos producen `1`. También cumple:

$$
A \oplus B \oplus B = A
$$

En un esquema de componentes, conocer solo una pieza no permite obtener la otra ni reconstruir la KEK. Si se obtienen ambas, sí se puede recomponer la clave. Por eso la separación debe acompañarse de controles organizativos; XOR por sí solo no protege dos componentes que estén juntos.

## 5. Paso 2: entender y calcular el KCV

### 5.1 Qué comprueba

Un KCV es una huella corta calculada desde una clave. Sirve para comprobar que la clave reconstruida o importada coincide con la esperada. **No sirve para recuperar la clave ni para cifrar datos.**

El flujo es:

```text
clave + bloque conocido -> algoritmo criptográfico -> resultado
resultado -> tomar los primeros 3 bytes -> escribirlos en hexadecimal -> KCV
```

Tres bytes se muestran como seis caracteres hexadecimales, porque cada byte necesita dos caracteres (`F7 4B 90` se escribe `F74B90`).

### 5.2 KCV exacto de la KEK de este reto

La KEK tiene 32 bytes, así que `crypto_utils.py` sigue su rama AES-256. El código calcula CMAC-AES sobre un bloque de 16 bytes cero:

$$
T = CMAC_{AES-256, KEK}(00\ 00\ \ldots\ 00)
$$

El bloque de entrada tiene exactamente 16 bytes. CMAC produce una etiqueta de 16 bytes. Con los datos de este reto, la salida completa calculada es:

```text
F74B9050C7E8D40716A7EEEC8A3B75CA
```

Ahora se toman los primeros tres bytes:

```text
salida completa: F7 4B 90 50 C7 E8 D4 07 16 A7 EE EC 8A 3B 75 CA
primeros 3 bytes: F7 4B 90
KCV:              F7 4B 90 -> F74B90
```

Ese `F74B90` coincide con el valor esperado que se introdujo en la GUI. Por eso la KEK se acepta.

### 5.3 KCV exacto de la BDK

La BDK extraída tiene 16 bytes, así que este programa usa Triple DES (3DES) en modo ECB sobre un bloque de 8 bytes cero:

$$
T = 3DES_{BDK}(00\ 00\ 00\ 00\ 00\ 00\ 00\ 00)
$$

Con la BDK del reto, la salida completa del bloque cifrado es:

```text
EABBDC0BBBFE30B1
```

Tomando los tres primeros bytes:

```text
salida completa: E A B B D C 0B BB FE 30 B1
primeros 3 bytes: E A B B D C
KCV:               E A B B D C -> EABBDC
```

El KCV calculado coincide con el KCV esperado de la BDK.

### 5.4 Por qué hay dos fórmulas

El formato del KCV depende del tipo/tamaño de clave en **esta implementación**:

| Clave | Tamaño en este reto | Operación que hace el código | Primeros 3 bytes |
|---|---:|---|---|
| KEK | 32 bytes, AES-256 | CMAC-AES sobre 16 bytes cero | `F74B90` |
| BDK | 16 bytes, 2-key TDES | 3DES-ECB sobre 8 bytes cero | `EABBDC` |

No se debe aplicar una fórmula universal a todas las claves. Si se emplea otra familia, otra convención de KCV o una longitud no admitida, el resultado será distinto. Por eso en el reto fue importante corregir el cálculo según la longitud y familia de la clave.

Un KCV de 3 bytes solo tiene 24 bits: puede detectar errores habituales, pero es demasiado corto para autenticar una clave con garantías criptográficas. La protección e integridad del key block TR-31 es una función distinta, realizada por la biblioteca TR-31.

## 6. Paso 3: abrir el bloque TR-31 y obtener la BDK

El valor entregado para la BDK es un bloque TR-31, no la clave BDK en claro:

```text
D0112B0TX00E000080BF1D76A239777F8C2B605EB4FCF6DC9B9CFC6A5170C18282BDAB7D4D4D4559BC6A952101BA74EF8C1563BC2A73BF76
```

Se puede pensar en él como un paquete protegido. Contiene un encabezado con atributos de la clave y material protegido con controles de integridad. El prefijo `D0112B0T` indica propiedades/uso del bloque; no es la BDK en claro.

La KEK validada se usa como KBPK (*Key Block Protection Key*) para que la implementación TR-31 abra y valide el bloque:

$$
BDK = unwrap_{KEK}(TR31\_block)
$$

La biblioteca devuelve:

```text
BDK = 39EDE3A9437F3FF561898D1F6FABBD25
```

La BDK tiene 16 bytes. Se calcula su KCV y se compara con `EABBDC`, como se explicó arriba. La aplicación no debe continuar con DUKPT si el bloque no se puede abrir o si el KCV no coincide.

### BDK no es PEK

El módulo de exportación genera una PEK y la envuelve con un encabezado distinto, que empieza con `D0144P...`. El key block recibido para este paso debe ser BDK (`D0112B0T...`). No son intercambiables: describen claves destinadas a usos diferentes.

## 7. Paso 4: derivar una clave DUKPT

### 7.1 Qué se quiere conseguir

La BDK es una clave raíz. En el esquema DUKPT, no se cifra cada transacción directamente con la BDK: la BDK y el KSN se procesan para derivar una clave correspondiente a esa transacción.

De forma conceptual:

$$
K_{transacción} = F(BDK, KSN)
$$

`F` representa el conjunto de operaciones DUKPT; no es una suma simple. Si cambia el KSN de transacción, cambia la clave derivada.

### 7.2 KSN del reto

El KSN usado por el bonus es:

```text
729C77361E9A51E000F2
```

Tiene 10 bytes. Su parte baja incluye un contador de 21 bits. En este valor, los últimos tres bytes son `E000F2`; al aplicar la máscara de contador `1FFFFF`, se obtiene:

```text
E000F2 AND 1FFFFF = 0000F2 = 242 decimal
```

El algoritmo usa los bits de ese contador para saber qué etapas de derivación aplicar. No usa solo el número `242`: también utiliza la parte de identificación/base del KSN y la BDK.

### 7.3 IPEK y clave derivada

La implementación local del proyecto hace, resumidamente:

1. Toma la BDK de 16 bytes y la expande a 24 bytes para 3DES repitiendo sus primeros 8 bytes: `BDK || BDK[0:8]`.
2. Pone a cero el contador del KSN para formar el KSN base.
3. Cifra la parte correspondiente del KSN base con 3DES para obtener dos mitades del IPEK; la segunda mitad utiliza la BDK modificada con la máscara definida por DUKPT.
4. Recorre los bits activos del contador. Para cada bit aplica las operaciones DES/XOR y máscaras de derivación definidas por el algoritmo.

Con los valores del reto, el IPEK intermedio es:

```text
DB833E79B68B868C285534462F0099B5
```

Y la clave DUKPT final que devuelve el código es:

```text
F0BBF26A9B1D48220ED642709E5C4454
```

La derivación es determinista: misma BDK y mismo KSN producen la misma clave; cambiar el KSN produce otra derivación. El IPEK sirve como valor intermedio y no es el ciphertext ni el mensaje claro.

## 8. Paso 5: descifrar el bonus

El ciphertext entregado al bonus es:

```text
FCC832A91953151148E86A01BE9420AC
```

La clave derivada de DUKPT se usa para descifrarlo con 3DES en modo ECB, según los datos y el formato de este ejercicio:

$$
P = 3DES^{-1}_{K_{DUKPT}}(C)
$$

La salida tiene 16 bytes:

```text
hex:   4D454C495F526F636B73210000000000
texto: MELI_Rocks!\x00\x00\x00\x00\x00
```

Los primeros 11 bytes son los caracteres UTF-8/ASCII de `MELI_Rocks!`; los cinco bytes finales `00` son relleno del dato de prueba. El programa los quita con `rstrip(b"\x00")` antes de decodificar el texto.

## 9. Resumen de entradas, operaciones y resultados

| Paso | Entrada | Operación | Resultado usado en el paso siguiente |
|---|---|---|---|
| Reconstrucción | `C1`, `C2` | XOR byte a byte | KEK `C5A5...4D61` |
| Validación KEK | KEK de 32 bytes | CMAC-AES(16 bytes cero), primeros 3 bytes | `F74B90` |
| Apertura de clave | KEK + bloque TR-31 | `unwrap` TR-31 | BDK `39ED...BD25` |
| Validación BDK | BDK de 16 bytes | 3DES-ECB(8 bytes cero), primeros 3 bytes | `EABBDC` |
| Derivación | BDK + KSN | Algoritmo DUKPT | `F0BB...4454` |
| Descifrado | clave DUKPT + ciphertext | 3DES-ECB decrypt | `MELI_Rocks!` |

# Parte 2. Cómo funciona el código y cómo verlo en la GUI

## 10. Archivos principales

| Archivo | Responsabilidad |
|---|---|
| `key_exchange/__main__.py` | Abre la GUI si se ejecuta sin argumentos; con argumentos conserva la entrada al CLI |
| `key_exchange/gui.py` | Construye las pestañas, campos, tarjetas de estado y coordina los pasos visibles |
| `key_exchange/crypto_utils.py` | XOR, cálculo/validación de KCV, creación de claves y operaciones TR-31 |
| `key_exchange/bonus.py` | Implementa la derivación DUKPT local y descifra el ciphertext del bonus |
| `key_exchange/cli.py` | Ofrece los mismos flujos de exportación/importación desde comandos |

La interfaz no implementa por su cuenta los algoritmos: recoge los datos, llama a las funciones criptográficas y muestra el resultado o error de cada etapa.

## 11. Cómo iniciar la interfaz

Desde la carpeta del proyecto:

```powershell
python -m key_exchange
```

El punto de entrada detecta que no hay argumentos y ejecuta `run_gui()`. Si se pasa un comando como `export-pek` o `import-bdk`, se usa el CLI en vez de abrir la ventana.

La ventana tiene dos pestañas:

- **Exportar PEK:** crea una clave nueva y la protege en un bloque TR-31.
- **Importar BDK:** abre el bloque BDK de referencia, valida la clave y ejecuta DUKPT.

## 12. Pestaña “Importar BDK”: correspondencia pantalla-código

Esta pestaña representa el flujo principal del reto. Los campos se precargan con los componentes, KCV esperados y bloque TR-31 de referencia.

| Lo que ves | Lo que hace el programa | Función/código relacionado |
|---|---|---|
| Componente KEK 1 y 2 | Convierte el hexadecimal en bytes y combina ambos | `xor_components()` en `crypto_utils.py` |
| KCV esperado KEK (`F74B90`) | Calcula el KCV de la KEK y compara | `calculate_cmac_kcv()` y `validate_cmac_kcv()` |
| Key block BDK | Comprueba el tipo de bloque y lo abre con la KEK | `unwrap_tr31()`; usa `KeyBlock` de `psec` |
| KCV esperado BDK (`EABBDC`) | Calcula el KCV de la BDK y compara | `calculate_cmac_kcv()` y `validate_cmac_kcv()` |
| Botón “Ejecutar importación paso a paso” | Llama a `_run_import()` | Método de `KeyExchangeApp` |

Al ejecutar, la GUI completa cuatro tarjetas en este orden:

1. **Recombinar componentes y validar KEK.** La tarjeta indica que la KEK pasó la comparación del KCV. Por diseño, no es necesario presentar la KEK en claro en esa tarjeta.
2. **Desenvolver key block TR-31.** Se obtiene la BDK. La implementación actual muestra su hexadecimal para que el ejercicio sea observable.
3. **Validar KCV de la BDK.** Solo se continúa si coincide con `EABBDC`.
4. **Derivar clave DUKPT y descifrar mensaje.** Se usa la BDK, el KSN y el ciphertext del bonus. La tarjeta muestra el texto y la clave derivada.

Si hay un error, la tarjeta pendiente correspondiente cambia a estado de error y aparece un mensaje. Por ejemplo, un KCV incorrecto detiene el flujo antes de desenvolver o derivar. Si se carga un bloque PEK (`D0144P...`), el programa lo rechaza porque se esperaba el bloque BDK (`D0112B0T...`).

## 13. Pestaña “Exportar PEK”: correspondencia pantalla-código

La pestaña de exportación no es otro modo de calcular la BDK. Demuestra el flujo inverso: crear una PEK y transportarla protegida con TR-31.

1. **Recombinar componentes y validar KEK.** Reutiliza los mismos componentes y cálculo de KCV.
2. **Generar PEK AES-256.** `generate_aes256_key()` usa una fuente aleatoria segura (`os.urandom(32)`). La PEK cambia en cada ejecución; eso es esperado. La GUI muestra su KCV, no necesita mostrar la PEK en claro.
3. **Envolver PEK en TR-31.** `wrap_tr31()` crea los atributos del key block para el uso PEK y lo protege usando la KEK. `gui.py` escribe el bloque en la ruta indicada, por defecto `pek_tr31.txt`.

El flujo de exportación, resumido:

```text
componentes -> KEK verificada -> PEK aleatoria -> PEK protegida en TR-31 -> archivo
```

## 14. Qué hace cada función criptográfica

### `xor_components(comp1_hex, comp2_hex)`

Convierte ambas cadenas hexadecimales en bytes, comprueba que tengan la misma longitud y aplica XOR byte por byte. Si el hexadecimal es inválido o las longitudes son distintas, lanza un error.

### `calculate_cmac_kcv(key)`

- 32 bytes: construye CMAC con AES-256, procesa 16 bytes cero, finaliza CMAC y devuelve los tres primeros bytes en hexadecimal mayúsculo.
- 16 o 24 bytes: cifra 8 bytes cero con Triple DES en ECB y devuelve los tres primeros bytes en hexadecimal mayúsculo.
- Otra longitud: lanza un error porque el programa no define un cálculo para ella.

### `validate_cmac_kcv(key, expected_kcv)`

Calcula el KCV y lo compara con el esperado ignorando diferencias entre minúsculas y mayúsculas. Si difieren, levanta un error con ambos valores para ayudar a diagnosticar.

### `wrap_tr31()` y `unwrap_tr31()`

Delegan el formato TR-31 a la biblioteca `psec`. En el flujo de importación, `unwrap_tr31()` recibe el bloque y la KEK, y devuelve la clave una vez que la biblioteca procesa el bloque.

### `LocalDUKPTServer` y `decrypt_bonus_dukpt()`

`LocalDUKPTServer` genera el IPEK y procesa el KSN para derivar la clave. `decrypt_bonus_dukpt()` usa esa clave para descifrar el ciphertext fijo del bonus y devuelve tanto la clave como los bytes descifrados. La GUI elimina el relleno nulo final y convierte esos bytes a texto.

## 15. Precisión y límites de seguridad

- Este es un ejercicio didáctico, no un HSM ni un sistema de pagos listo para producción.
- Los KCV de 3 bytes son comprobaciones cortas; no sustituyen autenticación criptográfica fuerte.
- TR-31 protege el transporte de claves y sus atributos; no debe confundirse con el KCV mostrado aparte.
- La interfaz de demostración muestra algunos valores sensibles, como la BDK y la clave derivada. En producción se evitaría exponerlos y se usaría un HSM y controles de acceso.
- El bonus usa 3DES-ECB porque esos son los algoritmos/datos definidos por este reto. No es una recomendación para diseñar cifrado nuevo.
- `TripleDES` aparece con avisos de obsolescencia en algunas versiones recientes de `cryptography`; esto no cambia el resultado de este ejercicio, pero sí sería una tarea de mantenimiento al migrar a una versión futura.

## 16. Resultado de referencia

Con los datos de ejemplo y el código actual, los resultados comprobados son:

```text
KEK       C5A5117469A79C794720B20989257444AD33FF4F7659851A0DD727F555E74D61
KCV KEK   F74B90
BDK       39EDE3A9437F3FF561898D1F6FABBD25
KCV BDK   EABBDC
DUKPT key F0BBF26A9B1D48220ED642709E5C4454
Mensaje   MELI_Rocks!
```
