/*
 * Copyright 2012-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.boot.logging.log4j2;

import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.FileConfigurationMonitor;
import org.hamcrest.Matcher;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import org.springframework.boot.logging.AbstractLoggingSystemTests;
import org.springframework.boot.logging.LogLevel;
import org.springframework.boot.testutil.Matched;
import org.springframework.boot.testutil.OutputCapture;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;

/**
 * Tests for {@link Log4J2LoggingSystem}.
 *
 * @author Daniel Fullarton
 * @author Phillip Webb
 * @author Andy Wilkinson
 */
public class Log4J2LoggingSystemTests extends AbstractLoggingSystemTests {

	@Rule
	public OutputCapture output = new OutputCapture();

	private final TestLog4J2LoggingSystem loggingSystem = new TestLog4J2LoggingSystem();

	private Logger logger;

	@Before
	public void setup() {
		this.logger = LogManager.getLogger(getClass());
	}

	@Test
	public void noFile() throws Exception {
		this.loggingSystem.beforeInitialize();
		this.logger.info("Hidden");
		this.loggingSystem.initialize(null, null, null);
		this.logger.info("Hello world");
		String output = this.output.toString().trim();
		Configuration configuration = this.loggingSystem.getConfiguration();
		assertThat(output).contains("Hello world").doesNotContain("Hidden");
		assertThat(new File(tmpDir() + "/spring.log").exists()).isFalse();
		assertThat(configuration.getConfigurationSource().getFile()).isNotNull();
	}

	@Test
	public void withFile() throws Exception {
		this.loggingSystem.beforeInitialize();
		this.logger.info("Hidden");
		this.loggingSystem.initialize(null, null, getLogFile(null, tmpDir()));
		this.logger.info("Hello world");
		String output = this.output.toString().trim();
		Configuration configuration = this.loggingSystem.getConfiguration();
		assertThat(output).contains("Hello world").doesNotContain("Hidden");
		assertThat(new File(tmpDir() + "/spring.log").exists()).isTrue();
		assertThat(configuration.getConfigurationSource().getFile()).isNotNull();
	}

	@Test
	public void testNonDefaultConfigLocation() throws Exception {
		this.loggingSystem.beforeInitialize();
		this.loggingSystem.initialize(null, "classpath:log4j2-nondefault.xml",
				getLogFile(tmpDir() + "/tmp.log", null));
		this.logger.info("Hello world");
		String output = this.output.toString().trim();
		Configuration configuration = this.loggingSystem.getConfiguration();
		assertThat(output).contains("Hello world").contains(tmpDir() + "/tmp.log");
		assertThat(new File(tmpDir() + "/tmp.log").exists()).isFalse();
		assertThat(configuration.getConfigurationSource().getFile().getAbsolutePath())
				.contains("log4j2-nondefault.xml");
		// we assume that "log4j2-nondefault.xml" contains the 'monitorInterval'
		// attribute, so we check that a monitor is created
		assertThat(configuration.getConfigurationMonitor())
				.isInstanceOf(FileConfigurationMonitor.class);
	}

	@Test(expected = IllegalStateException.class)
	public void testNonexistentConfigLocation() throws Exception {
		this.loggingSystem.beforeInitialize();
		this.loggingSystem.initialize(null, "classpath:log4j2-nonexistent.xml", null);
	}

	@Test
	public void setLevel() throws Exception {
		this.loggingSystem.beforeInitialize();
		this.loggingSystem.initialize(null, null, null);
		this.logger.debug("Hello");
		this.loggingSystem.setLogLevel("org.springframework.boot", LogLevel.DEBUG);
		this.logger.debug("Hello");
		assertThat(StringUtils.countOccurrencesOf(this.output.toString(), "Hello"))
				.isEqualTo(1);
	}

	@Test
	public void setLevelOfUnconfiguredLoggerDoesNotAffectRootConfiguration()
			throws Exception {
		this.loggingSystem.beforeInitialize();
		this.loggingSystem.initialize(null, null, null);
		LogManager.getRootLogger().debug("Hello");
		this.loggingSystem.setLogLevel("foo.bar.baz", LogLevel.DEBUG);
		LogManager.getRootLogger().debug("Hello");
		assertThat(this.output.toString()).doesNotContain("Hello");
	}

	@Test
	@Ignore("Fails on Bamboo")
	public void loggingThatUsesJulIsCaptured() {
		this.loggingSystem.beforeInitialize();
		this.loggingSystem.initialize(null, null, null);
		java.util.logging.Logger julLogger = java.util.logging.Logger
				.getLogger(getClass().getName());
		julLogger.severe("Hello world");
		String output = this.output.toString().trim();
		assertThat(output).contains("Hello world");
	}

	@Test
	public void configLocationsWithNoExtraDependencies() {
		assertThat(this.loggingSystem.getStandardConfigLocations())
				.contains("log4j2.xml");
	}

	@Test
	public void configLocationsWithJacksonDatabind() {
		this.loggingSystem.availableClasses(ObjectMapper.class.getName());
		assertThat(this.loggingSystem.getStandardConfigLocations())
				.contains("log4j2.json", "log4j2.jsn", "log4j2.xml");
	}

	@Test
	public void configLocationsWithJacksonDataformatYaml() {
		this.loggingSystem
				.availableClasses("com.fasterxml.jackson.dataformat.yaml.YAMLParser");
		assertThat(this.loggingSystem.getStandardConfigLocations())
				.contains("log4j2.yaml", "log4j2.yml", "log4j2.xml");
	}

	@Test
	public void configLocationsWithJacksonDatabindAndDataformatYaml() {
		this.loggingSystem.availableClasses(
				"com.fasterxml.jackson.dataformat.yaml.YAMLParser",
				ObjectMapper.class.getName());
		assertThat(this.loggingSystem.getStandardConfigLocations()).contains(
				"log4j2.yaml", "log4j2.yml", "log4j2.json", "log4j2.jsn", "log4j2.xml");
	}

	@Test
	public void springConfigLocations() throws Exception {
		String[] locations = getSpringConfigLocations(this.loggingSystem);
		assertThat(locations).isEqualTo(new String[] { "log4j2-spring.xml" });
	}

	@Test
	public void exceptionsIncludeClassPackaging() throws Exception {
		this.loggingSystem.beforeInitialize();
		this.loggingSystem.initialize(null, null, getLogFile(null, tmpDir()));
		Matcher<String> expectedOutput = containsString("[junit-");
		this.output.expect(expectedOutput);
		this.logger.warn("Expected exception", new RuntimeException("Expected"));
		String fileContents = FileCopyUtils
				.copyToString(new FileReader(new File(tmpDir() + "/spring.log")));
		assertThat(fileContents).is(Matched.by(expectedOutput));
	}

	@Test
	public void customExceptionConversionWord() throws Exception {
		System.setProperty("LOG_EXCEPTION_CONVERSION_WORD", "%ex");
		try {
			this.loggingSystem.beforeInitialize();
			this.logger.info("Hidden");
			this.loggingSystem.initialize(null, null, getLogFile(null, tmpDir()));
			Matcher<String> expectedOutput = Matchers.allOf(
					containsString("java.lang.RuntimeException: Expected"),
					not(containsString("Wrapped by:")));
			this.output.expect(expectedOutput);
			this.logger.warn("Expected exception",
					new RuntimeException("Expected", new RuntimeException("Cause")));
			String fileContents = FileCopyUtils
					.copyToString(new FileReader(new File(tmpDir() + "/spring.log")));
			assertThat(fileContents).is(Matched.by(expectedOutput));
		}
		finally {
			System.clearProperty("LOG_EXCEPTION_CONVERSION_WORD");
		}
	}

	private static class TestLog4J2LoggingSystem extends Log4J2LoggingSystem {

		private List<String> availableClasses = new ArrayList<String>();

		TestLog4J2LoggingSystem() {
			super(TestLog4J2LoggingSystem.class.getClassLoader());
		}

		public Configuration getConfiguration() {
			return ((org.apache.logging.log4j.core.LoggerContext) LogManager
					.getContext(false)).getConfiguration();
		}

		@Override
		protected boolean isClassAvailable(String className) {
			return this.availableClasses.contains(className);
		}

		private void availableClasses(String... classNames) {
			Collections.addAll(this.availableClasses, classNames);
		}

	}

}
