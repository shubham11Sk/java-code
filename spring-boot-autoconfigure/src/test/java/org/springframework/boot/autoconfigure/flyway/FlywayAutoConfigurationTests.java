/*
 * Copyright 2012-2014 the original author or authors.
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

package org.springframework.boot.autoconfigure.flyway;

import java.util.Arrays;

import javax.sql.DataSource;

import org.flywaydb.core.Flyway;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.boot.autoconfigure.PropertyPlaceholderAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceBuilder;
import org.springframework.boot.autoconfigure.jdbc.EmbeddedDataSourceConfiguration;
import org.springframework.boot.test.EnvironmentTestUtils;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests for {@link FlywayAutoConfiguration}.
 *
 * @author Dave Syer
 * @author Phillip Webb
 * @author Eddú Meléndez
 */
public class FlywayAutoConfigurationTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();;

	@Before
	public void init() {
		EnvironmentTestUtils.addEnvironment(this.context,
				"spring.datasource.name:flywaytest");
	}

	@After
	public void close() {
		if (this.context != null) {
			this.context.close();
		}
	}

	@Test
	public void noDataSource() throws Exception {
		registerAndRefresh(FlywayAutoConfiguration.class,
				PropertyPlaceholderAutoConfiguration.class);
		assertEquals(0, this.context.getBeanNamesForType(Flyway.class).length);
	}

	@Test
	public void createDataSource() throws Exception {
		EnvironmentTestUtils.addEnvironment(this.context,
				"flyway.url:jdbc:hsqldb:mem:flywaytest", "flyway.user:sa");
		registerAndRefresh(EmbeddedDataSourceConfiguration.class,
				FlywayAutoConfiguration.class, PropertyPlaceholderAutoConfiguration.class);
		Flyway flyway = this.context.getBean(Flyway.class);
		assertNotNull(flyway.getDataSource());
	}

	@Test
	public void flywayDataSource() throws Exception {
		registerAndRefresh(FlywayDataSourceConfiguration.class,
				EmbeddedDataSourceConfiguration.class, FlywayAutoConfiguration.class,
				PropertyPlaceholderAutoConfiguration.class);
		Flyway flyway = this.context.getBean(Flyway.class);
		assertNotNull(flyway.getDataSource());
	}

	@Test
	public void defaultFlyway() throws Exception {
		registerAndRefresh(EmbeddedDataSourceConfiguration.class,
				FlywayAutoConfiguration.class, PropertyPlaceholderAutoConfiguration.class);
		Flyway flyway = this.context.getBean(Flyway.class);
		assertEquals("[classpath:db/migration]", Arrays.asList(flyway.getLocations())
				.toString());
	}

	@Test
	public void overrideLocations() throws Exception {
		EnvironmentTestUtils.addEnvironment(this.context,
				"flyway.locations:classpath:db/changelog,classpath:db/migration");
		registerAndRefresh(EmbeddedDataSourceConfiguration.class,
				FlywayAutoConfiguration.class, PropertyPlaceholderAutoConfiguration.class);
		Flyway flyway = this.context.getBean(Flyway.class);
		assertEquals("[classpath:db/changelog, classpath:db/migration]",
				Arrays.asList(flyway.getLocations()).toString());
	}

	@Test
	public void overrideSchemas() throws Exception {
		EnvironmentTestUtils.addEnvironment(this.context, "flyway.schemas:public");
		registerAndRefresh(EmbeddedDataSourceConfiguration.class,
				FlywayAutoConfiguration.class, PropertyPlaceholderAutoConfiguration.class);
		Flyway flyway = this.context.getBean(Flyway.class);
		assertEquals("[public]", Arrays.asList(flyway.getSchemas()).toString());
	}

	@Test
	public void changeLogDoesNotExist() throws Exception {
		EnvironmentTestUtils.addEnvironment(this.context,
				"flyway.locations:file:no-such-dir");
		this.thrown.expect(BeanCreationException.class);
		registerAndRefresh(EmbeddedDataSourceConfiguration.class,
				FlywayAutoConfiguration.class, PropertyPlaceholderAutoConfiguration.class);
	}

	@Test
	public void checkLocationsAllMissing() throws Exception {
		EnvironmentTestUtils.addEnvironment(this.context,
				"flyway.locations:classpath:db/missing1,classpath:db/migration2",
				"flyway.check-location:true");
		this.thrown.expect(BeanCreationException.class);
		this.thrown.expectMessage("Cannot find migrations location in");
		registerAndRefresh(EmbeddedDataSourceConfiguration.class,
				FlywayAutoConfiguration.class, PropertyPlaceholderAutoConfiguration.class);
	}

	@Test
	public void checkLocationsAllExist() throws Exception {
		EnvironmentTestUtils.addEnvironment(this.context,
				"flyway.locations:classpath:db/changelog,classpath:db/migration",
				"flyway.check-location:true");
		registerAndRefresh(EmbeddedDataSourceConfiguration.class,
				FlywayAutoConfiguration.class, PropertyPlaceholderAutoConfiguration.class);
	}

	@Test
	public void overrideSqlMigrationPrefix() {
		EnvironmentTestUtils.addEnvironment(this.context, "flyway.sqlMigrationPrefix:R_");
		registerAndRefresh(EmbeddedDataSourceConfiguration.class,
			FlywayAutoConfiguration.class, PropertyPlaceholderAutoConfiguration.class);
		Flyway flyway = this.context.getBean(Flyway.class);
		assertEquals("R_", flyway.getSqlMigrationPrefix());
	}

	@Test
	public void overrideSqlMigrationSuffix() {
		EnvironmentTestUtils.addEnvironment(this.context, "flyway.sqlMigrationSuffix:.txt");
		registerAndRefresh(EmbeddedDataSourceConfiguration.class,
			FlywayAutoConfiguration.class, PropertyPlaceholderAutoConfiguration.class);
		Flyway flyway = this.context.getBean(Flyway.class);
		assertEquals(".txt", flyway.getSqlMigrationSuffix());
	}

	@Test
	public void overrideTable() {
		EnvironmentTestUtils.addEnvironment(this.context, "flyway.table:dbchangelog");
		registerAndRefresh(EmbeddedDataSourceConfiguration.class,
			FlywayAutoConfiguration.class, PropertyPlaceholderAutoConfiguration.class);
		Flyway flyway = this.context.getBean(Flyway.class);
		assertEquals("dbchangelog", flyway.getTable());
	}

	@Test
	public void overrideInitDescription() {
		EnvironmentTestUtils.addEnvironment(this.context, "flyway.baselineDescription:Starting migration");
		registerAndRefresh(EmbeddedDataSourceConfiguration.class,
			FlywayAutoConfiguration.class, PropertyPlaceholderAutoConfiguration.class);
		Flyway flyway = this.context.getBean(Flyway.class);
		assertEquals("Starting migration", flyway.getBaselineDescription());
	}

	@Test
	public void overrideBaselineOnMigrate() {
		EnvironmentTestUtils.addEnvironment(this.context, "flyway.baselineOnMigrate:true");
		registerAndRefresh(EmbeddedDataSourceConfiguration.class,
			FlywayAutoConfiguration.class, PropertyPlaceholderAutoConfiguration.class);
		Flyway flyway = this.context.getBean(Flyway.class);
		assertEquals(true, flyway.isBaselineOnMigrate());
	}

	@Test
	public void overrideValidateOnMigrate() {
		EnvironmentTestUtils.addEnvironment(this.context, "flyway.validateOnMigrate:false");
		registerAndRefresh(EmbeddedDataSourceConfiguration.class,
			FlywayAutoConfiguration.class, PropertyPlaceholderAutoConfiguration.class);
		Flyway flyway = this.context.getBean(Flyway.class);
		assertEquals(false, flyway.isValidateOnMigrate());
	}

	@Test
	public void overrideIgnoreFailedFutureMigration() {
		EnvironmentTestUtils.addEnvironment(this.context, "flyway.ignoreFailedFutureMigration:true");
		registerAndRefresh(EmbeddedDataSourceConfiguration.class,
			FlywayAutoConfiguration.class, PropertyPlaceholderAutoConfiguration.class);
		Flyway flyway = this.context.getBean(Flyway.class);
		assertEquals(true, flyway.isIgnoreFailedFutureMigration());
	}

	private void registerAndRefresh(Class<?>... annotatedClasses) {
		this.context.register(annotatedClasses);
		this.context.refresh();

	}

	@Configuration
	protected static class FlywayDataSourceConfiguration {

		@FlywayDataSource
		@Bean
		public DataSource flywayDataSource() {
			return DataSourceBuilder.create().url("jdbc:hsqldb:mem:flywaytest")
					.username("sa").build();
		}

	}
}
