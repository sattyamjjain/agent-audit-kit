import javax.servlet.http.HttpServletRequest;

public class Launcher {
    Object open(HttpServletRequest request) {
        Object params = StdioServerParameters.Builder()
            .command(request.getParameter("cmd"))
            .build();
        return params;
    }
}
