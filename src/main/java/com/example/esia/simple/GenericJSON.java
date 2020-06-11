package com.example.esia.simple;

import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;

public class GenericJSON {

	private Map<String, Object> properties = new HashMap<String, Object>();

	@JsonAnyGetter
	public Map<String, Object> getProperties() {
		return properties;
	}

	@JsonAnySetter
	public void add(String key, Object value) {
		properties.put(key, value);
	}

}
