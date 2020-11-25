## signapk

SignAPK for working in Android without any dependencies. (Only testkeys)  

**Another simple signapk mod!**  

I have modified SignApk.java from https://android.googlesource.com/platform/build/+/e691373514d47ecf29ce13e14e9f3b867d394693/tools/signapk for running in android too.

**Limitation for this is only testkeys are supported.**  

### Features:

-Fix OutOfMemoryError  
-JarSign, ZipAdjust and MinSign in a single stream  
-Use of @kellinwood zipio 1.8 will align the zip to 4 byte boundary  
-No need of ZipAdjusting separately.  

### Downloads:

Download **_signapk.jar_** from [releases](https://github.com/HemanthJabalpuri/signapk/releases).  

### Usage:

**In PC**  
For signing apks  
`java -jar signapk.jar in.apk out.apk`

For signing zips  
`java -jar signapk.jar -w in.zip out.zip`  

**In Android**  
For signing apks  
`dalvikvm -cp signapk.jar com.android.signapk.SignApk in.apk out.apk`

For signing zips  
`dalvikvm -cp signapk.jar com.android.signapk.SignApk -w in.zip out.zip`
