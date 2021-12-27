/*
 * Copyright 2012-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.boot.autoconfigure.batch;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;

import org.springframework.boot.sql.init.DatabaseInitializationSettings;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link BatchDataSourceScriptDatabaseInitializer}.
 *
 * @author Stephane Nicoll
 * @author Yanming Zhou
 */
class BatchDataSourceScriptDatabaseInitializerTests {

	@Test
	void getSettingsWithPlatformDoesNotTouchDataSource() {
		DataSource dataSource = mock(DataSource.class);
		BatchProperties properties = new BatchProperties();
		properties.getJdbc().setPlatform("test");
		DatabaseInitializationSettings settings = BatchDataSourceScriptDatabaseInitializer.getSettings(dataSource,
				properties.getJdbc());
		assertThat(settings.getSchemaLocations())
				.containsOnly("classpath:org/springframework/batch/core/schema-test.sql");
		then(dataSource).shouldHaveNoInteractions();
	}

}
