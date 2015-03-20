/*
 * Copyright 2012-2015 the original author or authors.
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

package org.springframework.boot.actuate.cache;

import java.lang.management.ManagementFactory;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.management.AttributeNotFoundException;
import javax.management.InstanceNotFoundException;
import javax.management.MBeanException;
import javax.management.MBeanServer;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectInstance;
import javax.management.ObjectName;
import javax.management.ReflectionException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.jcache.JCacheCache;

/**
 * {@link CacheStatisticsProvider} implementation for a JSR-107 compliant cache.
 *
 * @author Stephane Nicoll
 * @since 1.3.0
 */
class JCacheCacheStatisticsProvider implements CacheStatisticsProvider {

	private static final Logger logger = LoggerFactory.getLogger(JCacheCacheStatisticsProvider.class);

	private MBeanServer mBeanServer;

	private Map<JCacheCache, ObjectName> caches = new ConcurrentHashMap<JCacheCache, ObjectName>();

	@Override
	public CacheStatistics getCacheStatistics(Cache cache, CacheManager cacheManager) {
		if (cache instanceof JCacheCache) {
			return getCacheStatistics((JCacheCache) cache);
		}
		return null;
	}

	protected CacheStatistics getCacheStatistics(JCacheCache cache) {
		try {
			ObjectName objectName = getObjectName(cache);
			if (objectName != null) {
				return getCacheStatistics(objectName);
			}
			return null;
		}
		catch (MalformedObjectNameException e) {
			throw new IllegalStateException(e);
		}
	}

	protected CacheStatistics getCacheStatistics(ObjectName objectName) {
		MBeanServer mBeanServer = getMBeanServer();
		DefaultCacheStatistics stats = new DefaultCacheStatistics();
		Float hitPercentage = getAttribute(mBeanServer, objectName, "CacheHitPercentage", Float.class);
		Float missPercentage = getAttribute(mBeanServer, objectName, "CacheMissPercentage", Float.class);
		if ((hitPercentage != null && missPercentage != null) && (hitPercentage > 0 || missPercentage > 0)) {
			stats.setHitRatio(hitPercentage / (double) 100);
			stats.setMissRatio(missPercentage / (double) 100);
		}
		return stats;
	}

	protected ObjectName getObjectName(JCacheCache cache) throws MalformedObjectNameException {
		if (this.caches.containsKey(cache)) {
			return this.caches.get(cache);
		}

		Set<ObjectInstance> instances = getMBeanServer().queryMBeans(
				new ObjectName("javax.cache:type=CacheStatistics,Cache=" + cache.getName() + ",*"), null);
		if (instances.size() == 1) {
			ObjectName objectName = instances.iterator().next().getObjectName();
			this.caches.put(cache, objectName);
			return objectName;
		}
		return null; // None or more than one
	}

	protected MBeanServer getMBeanServer() {
		if (mBeanServer == null) {
			mBeanServer = ManagementFactory.getPlatformMBeanServer();
		}
		return mBeanServer;
	}

	private static <T> T getAttribute(MBeanServer mBeanServer, ObjectName objectName, String attributeName, Class<T> type) {
		try {
			Object attribute = mBeanServer.getAttribute(objectName, attributeName);
			return type.cast(attribute);
		}
		catch (MBeanException e) {
			throw new IllegalStateException(e);
		}
		catch (AttributeNotFoundException e) {
			throw new IllegalStateException("Unexpected: jcache provider does not " +
					"expose standard attribute " + attributeName, e);
		}
		catch (InstanceNotFoundException e) {
			logger.warn("Cache statistics are no longer available", e);
		}
		catch (ReflectionException e) {
			throw new IllegalStateException(e);
		}
		return null;
	}

}
