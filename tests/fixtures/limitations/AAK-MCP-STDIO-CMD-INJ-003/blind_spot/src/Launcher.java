import javax.servlet.http.HttpServletRequest;

public class Launcher {
    Object open(HttpServletRequest request) {
        ServerParameters params = ServerParameters.builder(request.getParameter("cmd"))
            .build();
        return new StdioClientTransport(params);
    }
}
