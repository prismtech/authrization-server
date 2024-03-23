package com.prismtech.security.controllers;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.prismtech.security.model.Articles;
import com.prismtech.security.model.EmployeeDetailsResponse;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Base64;
import java.util.List;

@Slf4j
@RestController
public class AuthController {
	Gson gson = new GsonBuilder().create();

	@Value("${auth.server.url}")
	String authServerUrl;

	@Value("${auth.client.username}")
	String authClientUsername;

	@Value("${auth.client.secret}")
	String authClientSecret;

	@Value("${resource.server.url}")
	String resourceServerUrl;

	@Value("${auth.client.redirectUri}")
	String redirectUriHost;

	@RequestMapping("/authorized-local")
	public Articles authorizedCodeLocally(@RequestParam String code) throws IOException {
		log.info("######################### authorized code accessing ###################################");
		log.info("Authorization Code={}", code);
		AccessToken accessToken;
		OkHttpClient client = new OkHttpClient().newBuilder()
				.build();

		RequestBody requestBody = new FormBody.Builder()
				.addEncoded("code", code)
				.addEncoded("grant_type", "authorization_code")
				.addEncoded("redirect_uri", redirectUriHost+"/authorized-local").build();

		String basicAuth = Base64.getEncoder().encodeToString(("client1" + ":" + "password").getBytes());
		Request request = new Request.Builder()
				.url(authServerUrl + "/oauth2/token")
				.method("POST", requestBody)
				.addHeader("Authorization", "Basic " + basicAuth)
				.addHeader("Content-Type", "application/x-www-form-urlencoded")
				.build();
		Response response = client.newCall(request).execute();
		String responseBody = response.body().string();
		log.info("Response body: " + responseBody);
		Gson gson = new GsonBuilder().create();
		accessToken = gson.fromJson(responseBody, AccessToken.class);
		return accessArticlesApi(accessToken.access_token);
	}

	@RequestMapping("/employee")
	public void getEmployee(@RequestParam String code) throws IOException {
		log.info("######################### employee  accessing ###################################");

		System.out.println("hello inside code");
	}

	@RequestMapping("/employee-session")
	public void getSession(@RequestParam String code) throws IOException {
		log.info("######################### employee session accessing ###################################");

		UserDetails userDetails = User.withUsername("user1")
				.password("password")
				.roles("USER")
				.build();
		PreAuthenticatedAuthenticationToken authentication = new PreAuthenticatedAuthenticationToken(userDetails, "",
				userDetails.getAuthorities());
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	@RequestMapping("/authorized")
	public EmployeeDetails authorizedCode(@RequestParam String code) throws IOException {
		log.info("######################### authorized code accessing ###################################");
		log.info("Authorization Code={}", code);
		AccessToken accessToken;
		OkHttpClient client = new OkHttpClient().newBuilder()
				.build();

		RequestBody requestBody = new FormBody.Builder()
				.addEncoded("code", code)
				.addEncoded("grant_type", "authorization_code")
				.addEncoded("redirect_uri", "http://127.0.0.1:8080/authorized").build();

		String basicAuth = Base64.getEncoder().encodeToString((authClientUsername + ":" + authClientSecret).getBytes());
		Request request = new Request.Builder()
				.url(authServerUrl + "/oauth2/token")
				.method("POST", requestBody)
				.addHeader("Authorization", "Basic " + basicAuth)
				.addHeader("Content-Type", "application/x-www-form-urlencoded")
				.build();
		Response response = client.newCall(request).execute();
		String responseBody = response.body().string();
		log.info("Response body: " + responseBody);
		Gson gson = new GsonBuilder().create();
		accessToken = gson.fromJson(responseBody, AccessToken.class);
		EmployeeDetails employeeDetails = new EmployeeDetails();
		employeeDetails.setEmployeeProfile(accessEmployeeProfileApi(accessToken.access_token));
		employeeDetails.setEmployeeList(accessEmployeeListApi());
		return employeeDetails;
	}

	private List<EmployeeDetailsResponse> accessEmployeeListApi() throws IOException {
		OkHttpClient client = new OkHttpClient().newBuilder().build();
		RequestBody requestBody = new FormBody.Builder()
				.addEncoded("grant_type", "client_credentials").build();

		String basicAuth = Base64.getEncoder().encodeToString((authClientUsername + ":" + authClientSecret).getBytes());
		Request request = new Request.Builder()
				.url(authServerUrl + "/oauth2/token")
				.method("POST", requestBody)
				.addHeader("Authorization", "Basic " + basicAuth)
				.addHeader("Content-Type", "application/x-www-form-urlencoded")
				.build();
		Response response = client.newCall(request).execute();
		String responseBody = response.body().string();
		log.info("Response body: " + responseBody);
		Gson gson = new GsonBuilder().create();
		AccessToken accessToken = gson.fromJson(responseBody, AccessToken.class);

		return callEmployeeListApi(accessToken.access_token);
	}

	private Articles accessArticlesApi(String accessToken) throws IOException {
		OkHttpClient client = new OkHttpClient().newBuilder()
				.build();
		Request request = new Request.Builder()
				.url(resourceServerUrl + "/resource-apis/articles-user")
				.get()
				.addHeader("Authorization", "Bearer " + accessToken)
				.addHeader("Content-Type", "application/json")
				.build();
		Response response = client.newCall(request).execute();
		String responseBody = response.body().string();
		log.info("Response body: {}", responseBody);
		return gson.fromJson(responseBody, Articles.class);
	}
	private EmployeeDetailsResponse accessEmployeeProfileApi(String accessToken) throws IOException {
		OkHttpClient client = new OkHttpClient().newBuilder()
				.build();
		Request request = new Request.Builder()
				.url(resourceServerUrl + "/resource/apis/employee-profile")
				.get()
				.addHeader("Authorization", "Bearer " + accessToken)
				.addHeader("Content-Type", "application/json")
				.build();
		Response response = client.newCall(request).execute();
		String responseBody = response.body().string();
		log.info("Response body: {}", responseBody);
		return gson.fromJson(responseBody, EmployeeDetailsResponse.class);
	}

	private List<EmployeeDetailsResponse> callEmployeeListApi(String accessToken) throws IOException {
		OkHttpClient client = new OkHttpClient().newBuilder()
				.build();
		Request request = new Request.Builder()
				.url(resourceServerUrl + "/resource/apis/employee-list?companyId=company1")
				.get()
				.addHeader("Authorization", "Bearer " + accessToken)
				.addHeader("Content-Type", "application/json")
				.build();
		Response response = client.newCall(request).execute();
		String responseBody = response.body().string();
		log.info("Response body: {}", responseBody);
		return gson.fromJson(responseBody, new TypeToken<List<EmployeeDetailsResponse>>() {}.getType());
	}

	@Data
	class AccessToken {
		String access_token;
		String scope;
		String token_type;
		String expires_in;
		String id_token;
	}

	@Data
	class EmployeeDetails {
		List<EmployeeDetailsResponse> employeeList;
		EmployeeDetailsResponse employeeProfile;
	}
}