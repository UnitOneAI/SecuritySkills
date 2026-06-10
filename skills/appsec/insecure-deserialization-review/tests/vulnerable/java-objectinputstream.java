import java.io.ObjectInputStream;
import jakarta.servlet.http.HttpServletRequest;

class ImportController {
    Object importState(HttpServletRequest request) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(request.getInputStream());
        Object payload = stream.readObject();
        applyImportedState(payload);
        return payload;
    }

    void applyImportedState(Object payload) {
        // Side effects happen after attacker-controlled object materialization.
    }
}
