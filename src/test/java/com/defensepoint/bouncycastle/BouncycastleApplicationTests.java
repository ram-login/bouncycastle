package com.defensepoint.bouncycastle;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = BouncycastleApplication.class)
class BouncycastleApplicationTests {

    @Autowired
    private WebApplicationContext context;

    private MockMvc restMockMvc;
    private JsonObject keysJsonObject;

    @BeforeEach
    public void setup() throws Exception {

        restMockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .build();

        MvcResult result = restMockMvc.perform(get("/BouncyCastle/GetKeys")
                .contentType("application/json"))
                .andExpect(status().isOk())
                .andReturn();

        keysJsonObject = new JsonParser().parse(result.getResponse().getContentAsString()).getAsJsonObject();
        assertThat(keysJsonObject.get("privateKey").getAsString()).isNotNull();
        assertThat(keysJsonObject.get("publicKey").getAsString()).isNotNull();
    }

    @Test
    void getSignature() throws Exception {
        restMockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .build();

        MvcResult result = restMockMvc.perform(post("/BouncyCastle/GetSignature")
                .contentType("application/json")
                .content(keysJsonObject.toString()))
                .andExpect(status().isOk())
                .andReturn();
    }

    @Test
    void getSignatureByStringKeys() throws Exception {
        restMockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .build();

        String publicKey = keysJsonObject.get("publicKey").toString();
        String privateKey = keysJsonObject.get("privateKey").toString();

        if(publicKey.charAt(0) == '\"') {
            publicKey = publicKey.substring( 1, publicKey.length() - 1 );
        }

        if(privateKey.charAt(0) == '\"') {
            privateKey = privateKey.substring( 1, privateKey.length() - 1 );
        }

        MvcResult result = restMockMvc.perform(post("/BouncyCastle/GetSignatureByStringKeys")
                .contentType("application/json")
                .param("publicKey", publicKey)
                .param("privateKey", privateKey))
                .andExpect(status().isOk())
                .andReturn();
    }
}
