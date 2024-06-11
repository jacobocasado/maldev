La inyección de shellcode es una de las técnicas más usadas por el malware en sistemas operativos Windows.
Esta técnica permite ejecutar código arbitrario (que está en forma de shellcode, de ahí el nombre) en el espacio de memoria de un proceso.
En otras palabras, podemos hacer que cualquier otro proceso ejecute código "inyectando" nuestro código.
## Por qué querríamos inyectar shellcode?
Esta técnica es muy interesante por las siguientes razones:
- Nuestro malware suele ser un proceso no persistente, con un tiempo de vida muy corto. La idea de inyectar shellcode es migrar a un proceso más duradero para mantener la ejecución de nuestro código (persistencia).
- Cambiar el contexto de ejecución: Es mucho más evasivo que un proceso como un navegador realice conexiones a un servidor externo a que lo haga un proceso como nuestro malware. También podemos inyectar nuestro shellcode en un proceso que esté firmado por Windows para que se ejecute bajo el contexto de este proceso. Los mecanismos de defensa son propensos a pasar más por alto comportamientos no deseados en procesos firmados por Windows (evasión)

Ya sea bien con el motivo de mantener persistencia, evadir defensas, o para cualquier otra cosa, esta técnica es comúnmente usada y tiene multitud de variantes. Es muy necesario entender el cómo funciona esta técnica de manera general y tener idea de algunas de sus variantes para, dependiendo de la situación, implementar una u otra en nuestro código.

## Pasos para inyectar shellcode
A pesar de haber una gran cantidad de implementaciones de inyección de shellcode (TBD listar algunas), todas comparten una serie de pasos a alto nivel que se listan a continuación para entender los fundamentos de esta técnica.
Los pasos son los siguientes:
1. Crear una región de memoria en el espacio de memoria del proceso al que se inyectará el shellcode.
2. Escribir el shellcode a la dirección de memoria creada.
3. Ejecutar el código que reside en la dirección de memoria creada.

Como hemos comentado anteriormente, cada implementación variará en cómo se realizan estos pasos, pero la idea es la misma.
## Creando nuestro primer inyector de shellcode en C++
Vamos a ver el ejemplo más clasico de inyección de shellcode, que consiste en inyectar shellcode en un proceso conociendo su PID.
Para ello, crearemos un programa en C++ y utilizaremos tres llamadas **muy comunes** de la API de Windows:
- `VirtualAllocEx` para crear la región de memoria en el proceso al que queremos inyectar el shellcode.
- `WriteProcessMemory` para escribir el shellcode en la dirección de memoria creada.
- `CreateRemoteThread` para iniciar un nuevo hilo en el proceso que ejecutará nuestra rutina de código.

Estas funciones están disponibles gracias a una librería que permite interactuar con el sistema operativo.
Te recomendamos que sigas los pasos para desarrollar este inyector manualmente; una vez que aprendas a implementar este inyector, tendrás la base para aprender como funcionan las técnicas más avanzadas de inyección de shellcode.

Antes de empezar, TBD 
![[attachments/Inyección de Shellcode (Shellcode injection).png]]



### Paso 1: Declarando nuestro shellcode
En este episodio no vamos a centrarnos en el paso de crear un shellcode personalizado que realice una tarea determinada, sino en inyectar dicho shellcode.
Dicho esto, es posible que en muchas ocasiones optemos por inyectar shellcode proporcionado por frameworks de explotación, como msfvenom, o Cobalt Strike.
En nuestro caso práctico, utilizaremos un shellcode funcional para Windows 7, 8, 10 y 11 de 64 bits (probado en dichas arquitecturas), el cual ejecutará el comando "calc.exe", lanzando una calculadora de Windows cuando este shellcode sea inyectado y ejecutado.
Para obtener este shellcode (y muchos otros) utilizaremos la herramienta msfvenom disponible en Kali Linux.

Con el siguiente comando podemos generar dicho shellcode:
```
msfvenom -p windows/x64/exec CMD="calc.exe" EXITFUNC=thread -f c
```

![[attachments/Inyección de Shellcode (Shellcode injection)-1.png]]