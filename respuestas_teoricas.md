# Preguntas Teóricas (Norma PCI PIN)

**1. ¿Podrían enviarse los dos componentes de la KEK por el mismo canal (por ejemplo, ambos por email)? ¿Qué problema habría?**
No. Esto violaría el principio de Conocimiento Dividido (Split Knowledge) y la Separación de Funciones (Separation of Duties) de PCI PIN. Si ambos componentes viajan por el mismo canal, cualquier persona (o atacante) con acceso a dicho canal podría interceptarlos y recombinarlos para obtener la KEK en claro, comprometiendo toda la arquitectura criptográfica.

**2. ¿Qué método alternativo se te ocurre para que la contraparte te entregue la KEK sin que viaje por componentes?**
- **Criptografía Asimétrica (RSA/ECC):** La KEK puede ir envuelta/cifrada con nuestra llave pública certificada por una PKI.
- **Distribución física segura:** Envío mediante Smart Cards integradas para cargar la llave de forma directa en el HSM.
- **Diffie-Hellman Authenticated Key Exchange:** Negociación criptográfica sobre canales autenticados.

**3. Si una de las dos partes que custodian las componentes de la KEK es comprometida, ¿queda comprometida la KEK?**
Desde un punto de vista puramente matemático no (efecto de One-Time Pad por el uso del XOR); el componente restante asegura la entropía de la KEK. Sin embargo, a nivel operativo y de cumplimiento, si el custodio comprometido tiene acceso al sistema donde se realiza la inyección de ambos componentes, existe el riesgo total.
