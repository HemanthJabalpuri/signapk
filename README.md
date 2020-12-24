## signapk

SignAPK for working in Android without any dependencies. (Only testkey)  

**Another simple signapk mod!**  

I have modified SignApk.java from https://android.googlesource.com/platform/build/+/e691373514d47ecf29ce13e14e9f3b867d394693/tools/signapk for running in android too.

### Description:

This is for who want to sign their RECOVERY flashable zip files for **_successful signature verification_**.  
It will successfully verify if the recovery is testkey supported (most recoveries support this).  
I have removed all the code related to signing APK files from SignApk.java. Because of this I renamed it to MinSignApk.

### Downloads:

Download **_MinSignApk.jar_** from [releases](https://github.com/HemanthJabalpuri/signapk/releases).  

### Usage:

**In PC**  
`java -jar MinSignApk.jar in.zip out.zip`  

**In Android**  
`dalvikvm -cp MinSignApk.jar com.android.signapk.SignApk in.zip out.zip`
