package org.mitre.oauth2.repository.impl

import org.eclipse.persistence.jpa.PersistenceProvider
import org.springframework.beans.factory.FactoryBean
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.core.io.ByteArrayResource
import org.springframework.core.io.DefaultResourceLoader
import org.springframework.core.io.Resource
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType
import org.springframework.orm.jpa.JpaTransactionManager
import org.springframework.orm.jpa.JpaVendorAdapter
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean
import org.springframework.orm.jpa.vendor.Database
import org.springframework.orm.jpa.vendor.EclipseLinkJpaVendorAdapter
import org.springframework.transaction.PlatformTransactionManager
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import javax.persistence.EntityManagerFactory
import javax.sql.DataSource

class TestDatabaseConfiguration {
    @Autowired
    private lateinit var jpaAdapter: JpaVendorAdapter

    @Autowired
    private lateinit var dataSource: DataSource

    @Autowired
    private lateinit var entityManagerFactory: EntityManagerFactory

    @Bean
    fun repository(): JpaOAuth2TokenRepository {
        return JpaOAuth2TokenRepository()
    }

    @Bean(name = ["defaultPersistenceUnit"])
    fun entityManagerFactory(): FactoryBean<EntityManagerFactory> {
        val factory = LocalContainerEntityManagerFactoryBean()
        factory.setPackagesToScan("org.mitre", "org.mitre")
        factory.setPersistenceProviderClass(PersistenceProvider::class.java)
        factory.persistenceUnitName = "test" + System.currentTimeMillis()
        factory.dataSource = dataSource
        factory.jpaVendorAdapter = jpaAdapter
        val jpaProperties: MutableMap<String, Any?> = HashMap()
        jpaProperties["eclipselink.weaving"] = "false"
        jpaProperties["eclipselink.logging.level"] = "INFO"
        jpaProperties["eclipselink.logging.level.sql"] = "INFO"
        jpaProperties["eclipselink.cache.shared.default"] = "false"
        factory.jpaPropertyMap = jpaProperties

        return factory
    }

    @Bean
    fun dataSource(): DataSource {
        return EmbeddedDatabaseBuilder(object : DefaultResourceLoader() {
            override fun getResource(location: String): Resource {
                val sql: String
                try {
                    sql = String(
                        Files.readAllBytes(
                            Paths.get(
                                "..", "openid-connect-server-webapp", "src", "main",
                                "resources", "db", "hsql", location
                            )
                        ), StandardCharsets.UTF_8
                    )
                } catch (e: IOException) {
                    throw RuntimeException("Failed to read sql-script $location", e)
                }

                return ByteArrayResource(sql.toByteArray(StandardCharsets.UTF_8))
            }
        }).generateUniqueName(true).setScriptEncoding(StandardCharsets.UTF_8.name()).setType(EmbeddedDatabaseType.HSQL)
            .addScripts("hsql_database_tables.sql").build()
    }

    @Bean
    fun jpaAdapter(): JpaVendorAdapter {
        val adapter = EclipseLinkJpaVendorAdapter()
        adapter.setDatabase(Database.HSQL)
        adapter.setShowSql(true)
        return adapter
    }

    @Bean
    fun transactionManager(): PlatformTransactionManager {
        val platformTransactionManager = JpaTransactionManager()
        platformTransactionManager.entityManagerFactory = entityManagerFactory
        return platformTransactionManager
    }
}
