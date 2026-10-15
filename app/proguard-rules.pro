# System Honor provider is loaded by its device-side FQCN; it is not packaged in this APK.
# Preserve readable diagnostic names without retaining unused application/library classes.
-keep,allowshrinking,allowoptimization class com.example.integrityprobe.HonorKeyBackend { *; }
-keep,allowshrinking,allowoptimization class com.example.integrityprobe.VendorSigningRunner { *; }

# Deliberately no broad "-keep org.bouncycastle.**". Production only uses direct
# certificate/ASN.1 helpers; software crypto uses platform JCA, not BC's reflective registry.
