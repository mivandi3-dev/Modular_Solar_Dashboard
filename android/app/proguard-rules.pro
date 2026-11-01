# Solarni monitor – R8 (5.0.2, audit A-09)
# Metode mosta prema JavaScriptu (window.SolariAndroid) moraju ostati s istim imenima.
-keepclassmembers class hr.ivandic.solarnimonitor.MainActivity$Bridge {
    @android.webkit.JavascriptInterface public *;
}
-keepattributes JavascriptInterface
