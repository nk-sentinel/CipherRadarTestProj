// Consumes the version catalog in gradle/libs.versions.toml via libs.* aliases.
// Enrichment resolves each alias to a concrete Maven coordinate + version.
plugins {
    `java-library`
}

dependencies {
    implementation(libs.jjwt.api)
    runtimeOnly(libs.jjwt.impl)
    implementation(libs.google.tink)
    implementation(libs.bouncycastle.bcprov)
}
