
Módulo 75 - Volcado de la Base de Datos SAM
Alternar Progreso
Ancho de Pantalla
Objetivos
Índice
Terminal
Descargar
Volcado de la Base de Datos SAM
Introducción a la Autenticación
Antes de poder interactuar con un sistema Windows, un usuario debe demostrar su identidad mediante la autenticación. La autenticación es el proceso de verificar la identidad de una persona u objeto. Para adaptarse a diferentes escenarios de autenticación, Windows admite múltiples tipos de autenticación, que varían en longitud y complejidad.

Autenticación Interactiva
La autenticación interactiva se utiliza para otorgar acceso tanto a recursos locales como de dominio. Comienza cuando un usuario proporciona un conjunto de credenciales (por ejemplo, contraseña, tarjeta inteligente, certificado) y, si tiene éxito, termina con la creación de un token de acceso.

Un token de acceso sirve como contexto de seguridad de un proceso o hilo y contiene información como la identidad y privilegios del usuario. Al interactuar con un objeto asegurable, el sistema utiliza el token para determinar si el usuario tiene derechos suficientes para realizar la acción solicitada. Un objeto se considera asegurable si tiene un descriptor de seguridad, que es una estructura de datos que contiene información de seguridad sobre el objeto. Esta información incluye una lista de control de acceso discrecional (DACL), que define quién tiene acceso al objeto y su nivel de acceso.

Para los fines de la autenticación, Windows utiliza un dominio. Un dominio asocia un conjunto de usuarios y grupos con una política, que gobierna las acciones que pueden realizar y los recursos a los que pueden acceder. También proporciona infraestructura de gestión para estas entidades, incluida la infraestructura de inicio de sesión. La arquitectura de dominio es lo suficientemente compleja como para justificar un curso completo, por lo que comenzaremos familiarizándonos con el proceso de autenticación de la forma más simple de un dominio: el dominio local.

El Dominio Local
Aunque los dominios a menudo se asocian con redes empresariales, cada computadora, ya sea independiente o parte de una red, pertenece a un dominio conocido como dominio local. Este dominio generalmente pasa desapercibido porque comparte el mismo nombre que la computadora misma.

En este escenario, la política de seguridad local se aplica a usuarios y grupos locales. Mantenida por la Autoridad de Seguridad Local (LSA), incluye información como:

Derechos de cuenta - Los privilegios asignados al token de un usuario cuando inicia sesión.

Derechos de inicio de sesión - Qué tipos de autenticación puede realizar un usuario o grupo. Por ejemplo, se pueden usar para negar a un usuario la autenticación a través de la red.

Política de auditoría de seguridad - Gobierna qué eventos se registrarán en el registro de eventos y las condiciones bajo las cuales se registrarán, como éxito o fracaso.

La LSA también es responsable de la gestión del dominio local. Para este fin, mantiene dos bases de datos almacenadas como claves de registro: la base de datos SAM y la base de datos de política LSA:

La base de datos del Administrador de Cuentas de Seguridad (SAM) contiene información de inicio de sesión sobre grupos y usuarios locales, como nombres de usuario, hashes de contraseñas, identificadores de seguridad (SID) y membresías de grupos. Al autenticarse en el dominio local, la LSA calcula un hash de tu contraseña y lo compara con el almacenado en el SAM.

Por otro lado, la base de datos de política LSA contiene la política de seguridad local descrita anteriormente. Profundizaremos en la política LSA en un módulo posterior.

Autenticación de Red
En ciertos escenarios, una aplicación o servicio puede necesitar acceder a recursos de red, como un recurso compartido de archivos. Este tipo de autenticación utiliza credenciales previamente establecidas y generalmente es transparente a menos que se deban especificar credenciales alternativas. Windows admite múltiples protocolos de autenticación de red, que exploraremos más adelante.

Volcado de la Base de Datos SAM
La base de datos SAM se encuentra en Registry\Machine\SAM y solo puede ser accedida por NT AUTHORITY\SYSTEM. Alternativamente, podemos evitar las comprobaciones de acceso a través del privilegio SeBackupPrivilege. La función CanAccessSam determina si podemos acceder al SAM consultando primero el Identificador de Seguridad (SID) del usuario asociado con nuestro proceso. Luego, construye el SID de la cuenta NT AUTHORITY\SYSTEM y compara los dos. Si son iguales, podemos proceder simplemente. De lo contrario, intentamos adquirir el privilegio SeBackupPrivilege. Si fallamos, no podemos acceder al SAM.

Primero, crearemos una función auxiliar que será utilizada por la función CanAccessSam que verifica si el SID proporcionado es el de NT AUTHORITY\SYSTEM. La función IsSidLocalSystem tiene un parámetro Sid que es el ID del usuario. Luego usa RtlAllocateAndInitializeSid para construir el SID de NT AUTHORITY\SYSTEM, siendo S-1-5-18. Finalmente, se hace una comparación usando RtlEqualSid que, si es verdadera, significa que el SID dado coincide con NT AUTHORITY\SYSTEM.

La función IsSidLocalSystem tiene un parámetro, Sid, que es un puntero al SID que se va a comparar con S-1-5-18.

```c
BOOLEAN IsSidLocalSystem(_In_ PSID Sid)
{
    //
    // Necesitamos la Autoridad de Identificador NT, representada por el "5" en "S-1-5-18", y el RID del Sistema Local, que coincide con "18"
    //

	PSID                     LocalSystemSid;
	SID_IDENTIFIER_AUTHORITY IdentifierAuthority = SECURITY_NT_AUTHORITY;
	NTSTATUS                 Status = RtlAllocateAndInitializeSid(&IdentifierAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &LocalSystemSid);

	if (!NT_SUCCESS(Status))
	{
		wprintf(L"No se pudo inicializar el SID de NT AUTHORITY\\SYSTEM: 0x%08lX", Status);
		return FALSE;
	}

	BOOLEAN Result = RtlEqualSid(Sid, LocalSystemSid);
	RtlFreeSid(LocalSystemSid);
	return Result;
}
```

La función CanAccessSam tiene un parámetro, NtOpenKeyExPointer, que es un puntero de función a NtOpenKeyEx. Esto nos informa bajo qué circunstancias estamos accediendo al SAM. Si el parámetro no está establecido, somos NT AUTHORITY\SYSTEM y podemos simplemente usar NtOpenKey para acceder a las claves SAM. En el otro caso, debemos usar NtOpenKeyEx con la bandera REG_OPTION_BACKUP_RESTORE. Dado que NtOpenKeyEx solo está disponible en Windows 7 y superior, lo resolveremos dinámicamente y fallaremos si no está presente.

Volcado de información del dominio local
Windows almacena el hash MD4 de la contraseña de cada usuario local. Este hash se conoce comúnmente como hash NT. Por razones de compatibilidad, Windows solía almacenar un hash adicional de LAN Manager (LM). Esta característica ha sido deshabilitada de forma predeterminada desde Windows Vista.

Desafortunadamente, el volcado de hashes NT no es trivial ya que están sujetos a múltiples capas de ofuscación: Primero, el hash NT se cifra con el algoritmo DES donde la clave es el identificador relativo (RID) del usuario correspondiente. El RID es un número único asignado a cada principio de seguridad (como un usuario o grupo) dentro de un dominio; en este escenario, el dominio local. Luego, el hash cifrado con DES se cifra usando la clave de cifrado de contraseña (PEK). El PEK, a su vez, se cifra usando la clave del sistema LSA.

El acceso a estos hashes es útil porque el débil algoritmo de hash los hace fácilmente descifrables. No obstante, puedes usar pass-the-hash para realizar autenticación de red sin conocer la contraseña en texto plano. Esta técnica se explorará en un módulo posterior.

Como se mencionó anteriormente, el primer paso para recuperar hashes NT es adquirir la clave del sistema LSA. Esta clave de 16 bytes se divide entre el atributo ClassName de cuatro claves de registro, con cada clave conteniendo cuatro bytes de la clave del sistema LSA. Todas estas claves son subclaves de la clave de configuración LSA, que está en \Registry\Machine\SYSTEM\CurrentControlSet\Control\Lsa\. Las subclaves específicas son:

\Registry\Machine\SYSTEM\CurrentControlSet\Control\Lsa\JD

\Registry\Machine\SYSTEM\CurrentControlSet\Control\Lsa\Skew1

\Registry\Machine\SYSTEM\CurrentControlSet\Control\Lsa\GBG

\Registry\Machine\SYSTEM\CurrentControlSet\Control\Lsa\Data

Además, se debe realizar una serie de permutaciones en los bytes de la clave para lograr su valor verdadero. Tenga en cuenta que la clave del sistema LSA difiere de sistema a sistema.

Volcado de hashes de contraseñas
Equipados con esta información, podemos formar un plan para volcar todos los hashes de contraseñas en el sistema:

Iteraremos a través de todas las subclaves de \Registry\Machine\SAM\SAM\Domains\Account\Users y consultaremos el valor F. Al igual que los atributos fijos del dominio, los atributos fijos del usuario contienen información almacenada para cada usuario en el dominio local.

Luego, consultaremos el valor V, que contiene los atributos de usuario Variables. Son "variables" porque, a diferencia de los atributos fijos, no todos están presentes para cada usuario local.

Finalmente, descifraremos e imprimiremos los hashes descritos por los atributos relacionados con la contraseña, a saber, NTLMHash, LMHash, NTLMHistory y LMHistory.

Demostración
Ejemplo de salida de datos fijos del dominio:
- Versión del dominio
- Contador de modificaciones del dominio
- Tiempo de creación
- Edad mínima/máxima de contraseña
- Próximo RID disponible
- Política de forzar cierre de sesión
- Umbral de bloqueo
- Propiedades de contraseña

Ejemplo de salida para un usuario:
- Atributos fijos (última sesión, última modificación de contraseña, expiración de cuenta, etc.)
- Atributos variables (nombre completo, comentario, directorio home, ruta de perfil, etc.)
- Hash NT
- Hash LM (si existe)
- Historial de contraseñas NT y LM

Índice de Contenidos
Volcado de la Base de Datos SAM
Introducción a la Autenticación
Autenticación Interactiva
El Dominio Local
Autenticación de Red
Volcado de la Base de Datos SAM
Volcado de información del dominio local
Volcado de hashes de contraseñas
Demostración
Anterior
Módulos
Completo
Siguiente
