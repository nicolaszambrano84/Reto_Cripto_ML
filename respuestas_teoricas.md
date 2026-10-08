¿Podrían enviarse los dos componentes de la KEK por el mismo canal?

Con base en las buenas prácticas y disposiciones enmarcadas en normativas como PCI DSS y PCI PIN, se deben adoptar medidas para una gestión, transmisión y almacenamiento seguro de material criptográfico. En este sentido, de ninguna manera se debería enviar los dos componentes de la KEK por un mismo canal, ya que esto representa un riesgo de que la información sea filtrada producto de una posible interceptación o acceso no autorizado al medio por el cual se enviaron ambos componentes.

Esto va en contra del principio de Conocimiento Dividido (Split Knowledge) y Control Dual (Dual Control), donde dos actores distintos conocen una parte del secreto, de manera que si alguno es filtrado no se expone la totalidad de la KEK, asegurando que esta no pueda ser descifrada por un actor malintencionado.

Normativa aplicable
PCI DSS (Requisito 3.6.1.2)
PCI PIN (Anexo A, Gestión de Llaves Simétricas)

¿Qué método alternativo se te ocurre para que la contraparte te entregue la KEK sin que viaje por componentes?

Emplear un intercambio de llaves basado en Infraestructura de Llave Pública (PKI). La criptografía asimétrica es el estándar para proteger transacciones de alta confidencialidad y resulta ideal para compartir secretos como la KEK. En este esquema, el emisor cifra la llave simétrica utilizando la clave pública del destinatario; esto permite que la KEK viaje de forma segura a través de un canal estándar, garantizando que únicamente el receptor legítimo, quien custodia la clave privada correspondiente, pueda descifrar y acceder al material criptográfico.

Si una de las dos partes que custodian las componentes de la KEK es comprometida, ¿queda comprometida la KEK?

La filtración de un solo componente no compromete la KEK. Debido a que la llave se ensambla mediante operaciones lógicas (XOR) y no por concatenación, tener una de las partes no otorga ninguna ventaja matemática al atacante. Para obtener la llave final, un actor malicioso se vería obligado a realizar un ataque de fuerza bruta sobre el componente faltante, enfrentándose a miles de millones de combinaciones posibles. Esto hace que descifrar el secreto por este medio sea computacionalmente inviable, cumpliendo así con el objetivo de mitigación de riesgos del conocimiento dividido.
