package benchmark;

// Exercises the expanded Java crypto-library import inventory rules
// (cbom-java-crypto-library-import) plus dependency enrichment against the
// root pom.xml:
//   - jjwt-api / jjwt-impl  -> resolved via <dependencyManagement> fallback
//   - tink                  -> resolved via a directly pinned <dependency>
//   - spring-security-crypto, commons-codec, nimbus-jose-jwt -> detected as
//     libraries but unresolved (no manifest entry), so library-only, no purl.
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.aead.AeadConfig;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.apache.commons.codec.digest.DigestUtils;
import com.nimbusds.jose.JWSObject;

public class CryptoLibraryImports {

    String issueToken(byte[] keyBytes) {
        var key = Keys.hmacShaKeyFor(keyBytes);
        return Jwts.builder().subject("svc").signWith(key).compact();
    }

    Aead tinkAead() throws Exception {
        AeadConfig.register();
        return null;
    }

    String bcryptHash(String pw) {
        return new BCryptPasswordEncoder().encode(pw);
    }

    String sha256Hex(String s) {
        return DigestUtils.sha256Hex(s);
    }

    boolean verify(JWSObject jws) {
        return jws != null;
    }
}
