package com.example.app;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Payload {
	public int nbf;
	public String scope;
	public String iss;
	 @JsonProperty("urn:esia:sid") public String urn_esia_sid;
	 @JsonProperty("urn:esia:sbj_id") public int urn_esia_sbj_id;
	public int exp;
	public int iat;
	public String client_id;
}
