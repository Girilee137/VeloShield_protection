package com.veloshield.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;

public class JsonUtil {

    private static final ObjectMapper mapper = new ObjectMapper();

    static {
        mapper.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
        mapper.findAndRegisterModules();
    }

    public static String toJson(Object obj) {
        try {
            return mapper.writeValueAsString(obj);
        } catch (IOException e) {
            throw new RuntimeException("JSON serialization failed: " + e.getMessage(), e);
        }
    }

    @SuppressWarnings("unchecked")
    public static <T> T fromJson(String json, Class<T> clazz) {
        try {
            return mapper.readValue(json, clazz);
        } catch (IOException e) {
            throw new RuntimeException("JSON deserialization failed: " + e.getMessage(), e);
        }
    }

    public static ObjectMapper getMapper() {
        return mapper;
    }
}
