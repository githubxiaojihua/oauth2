package cn.zetark.oauth2.web.filter;

import cn.zetark.oauth2.Constants;
import cn.zetark.oauth2.entity.Status;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.apache.oltu.oauth2.common.message.types.ParameterStyle;
import org.apache.oltu.oauth2.rs.request.OAuthAccessResourceRequest;
import org.apache.oltu.oauth2.rs.response.OAuthRSResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Oauth2Filter implements Filter{

    
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletResponse res = (HttpServletResponse) response;
        try {
            //1、根据普通request请求构建OAuth资源请求(从请求串中获取参数)从请求参数串中查询相关数据，也可以从请求头和body中查询
            OAuthAccessResourceRequest oauthRequest = new OAuthAccessResourceRequest((HttpServletRequest) request, ParameterStyle.QUERY); // queryString 方式获取参数
            //从header中获取参数
            // OAuthAccessResourceRequest oauthRequest = new OAuthAccessResourceRequest((HttpServletRequest) request, ParameterStyle.HEADER); // 从HttpHead头中获取参数

            //2、获取accessToken
            String accessToken = oauthRequest.getAccessToken();

            //3、验证Access Token
            if (!checkAccessToken(accessToken)) {
                // 如果不存在/过期了，返回未验证错误，需重新验证
                oAuthFaileResponse(res);
            }
            chain.doFilter(request, response);
        } catch (OAuthProblemException e) {
            try {
                oAuthFaileResponse(res);
            } catch (OAuthSystemException ex) {
                Logger.getLogger(getClass().getName()).log(Level.SEVERE, "error trying to access oauth server", ex);
            }
        }
        catch (OAuthSystemException e) {
            Logger.getLogger(getClass().getName()).log(Level.SEVERE, "error trying to access oauth server", e);
        }
    }

    /**
     * oAuth认证失败时的输出
     * @param res
     * @throws OAuthSystemException
     * @throws IOException
     */
    private void oAuthFaileResponse(HttpServletResponse res) throws OAuthSystemException, IOException {
        OAuthResponse oauthResponse = OAuthRSResponse
                .errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                .setRealm(Constants.RESOURCE_SERVER_NAME)
                .setError(OAuthError.ResourceResponse.INVALID_TOKEN)
                .buildHeaderMessage();
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add("Content-Type", "application/json; charset=utf-8");
        Gson gson = new GsonBuilder().create();
        res.addHeader(OAuth.HeaderType.WWW_AUTHENTICATE, oauthResponse.getHeader(OAuth.HeaderType.WWW_AUTHENTICATE));
        PrintWriter writer = res.getWriter();
        writer.write(gson.toJson(getStatus(HttpStatus.UNAUTHORIZED.value(),Constants.INVALID_ACCESS_TOKEN)));
        writer.flush();
        writer.close();
    }

    /**
     * 验证accessToken
     * @param accessToken
     * @return
     * @throws IOException
     */
    private boolean checkAccessToken(String accessToken) throws IOException {
        //使用java.net包下的URL与HttpURLConnection发送http请求调用AccessTokenController的checkAccessToken方法来验证token
        URL url = new URL(Constants.CHECK_ACCESS_CODE_URL+accessToken);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.disconnect();
        return HttpServletResponse.SC_OK == conn.getResponseCode();
    }

    private Status getStatus(int code,String msg){
        Status status = new Status();
        status.setCode(code);
        status.setMsg(msg);
        return status;
    }

    
    public void destroy() {

    }


}
