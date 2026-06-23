package benchmark.gradle;

// Library imports here resolve against the nearest-ancestor manifest, which is
// this module's build.gradle.kts -> gradle/libs.versions.toml catalog (not the
// repo-root pom.xml). jjwt + tink should carry catalog-resolved purls.
import io.jsonwebtoken.Jwts;
import com.google.crypto.tink.Aead;

public class CatalogApp {
    String token() {
        return Jwts.builder().subject("catalog").compact();
    }

    Aead aead() {
        return null;
    }
}
