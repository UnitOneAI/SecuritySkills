import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.InputStream;

final class ProfileImport {
    public String displayName;
    public String timezone;
}

class ImportController {
    private final ObjectMapper mapper = new ObjectMapper();

    ProfileImport importJson(InputStream requestBody) throws Exception {
        ProfileImport profile = mapper.readValue(requestBody, ProfileImport.class);
        validate(profile);
        return profile;
    }

    Object readLegacyInternalBlob(InputStream trustedInternalStream) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(trustedInternalStream);
        stream.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
            "com.example.dto.ProfileImport;java.base/*;!*"
        ));
        return stream.readObject();
    }

    void validate(ProfileImport profile) {
        if (profile.displayName == null || profile.displayName.length() > 80) {
            throw new IllegalArgumentException("invalid display name");
        }
    }
}
