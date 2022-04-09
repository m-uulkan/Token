package peaksoft.dto;

public class UserResponse {
    private final String jwtToken;

    public UserResponse(String jwtToken) {
        this.jwtToken = jwtToken;
    }

    public String getJwt() {
        return jwtToken;
    }
}
