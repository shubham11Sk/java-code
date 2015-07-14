package org.springframework.boot.actuate.endpoint.mvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.HashMap;
import java.util.Map;

import org.elasticsearch.common.collect.Maps;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.autoconfigure.EndpointWebMvcAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.ManagementServerPropertiesAutoConfiguration;
import org.springframework.boot.actuate.endpoint.InfoEndpoint;
import org.springframework.boot.actuate.endpoint.mvc.InfoMvcEndpointTests.TestConfiguration;
import org.springframework.boot.actuate.info.InfoProvider;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.web.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.web.WebMvcAutoConfiguration;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Tests for {@link InfoMvcEndpointTests}
 *
 * @author Meang Akira Tanaka
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = { TestConfiguration.class })
@WebAppConfiguration
public class InfoMvcEndpointTests {
	@Autowired
	private WebApplicationContext context;

	private MockMvc mvc;

	@Before
	public void setUp() {

		this.context.getBean(InfoEndpoint.class).setEnabled(true);
		this.mvc = MockMvcBuilders.webAppContextSetup(this.context).build();
	}

	@Test
	public void home() throws Exception {
		this.mvc.perform(get("/info")).andExpect(status().isOk())
		.andExpect(content().string(containsString("\"beanName2\":{\"key22\":\"value22\",\"key21\":\"value21\"},\"beanName1\":{\"key12\":\"value12\",\"key11\":\"value11\"}")));
	}
	
	@Import({ JacksonAutoConfiguration.class,
		HttpMessageConvertersAutoConfiguration.class,
		EndpointWebMvcAutoConfiguration.class,
		WebMvcAutoConfiguration.class,
		ManagementServerPropertiesAutoConfiguration.class })
	@Configuration
	public static class TestConfiguration {

		private Map<String, InfoProvider> infoProviders = Maps.newHashMap();

		public TestConfiguration() {
			InfoProvider infoProvider1 = new InfoProvider() {
				
				@Override
				public Map<String, Object> provide() {
					Map<String, Object> result = Maps.newHashMap();
					result.put("key11", "value11");
					result.put("key12", "value12");
					return result;
				}
			};
			infoProviders.put("beanName1", infoProvider1);
			
			InfoProvider infoProvider2 = new InfoProvider() {
				
				@Override
				public Map<String, Object> provide() {
					Map<String, Object> result = Maps.newHashMap();
					result.put("key21", "value21");
					result.put("key22", "value22");
					return result;
				}
			};
			infoProviders.put("beanName2", infoProvider2);
		}
		
		@Bean
		public InfoEndpoint endpoint() {
			return new InfoEndpoint(new HashMap<String, String>(), infoProviders);
		}

	}
	
}
