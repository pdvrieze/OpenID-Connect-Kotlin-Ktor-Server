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
        return LocalContainerEntityManagerFactoryBean().also {
            it.setPackagesToScan("org.mitre", "org.mitre")
            it.setPersistenceProviderClass(PersistenceProvider::class.java)
            it.persistenceUnitName = "test${System.currentTimeMillis()}"
            it.dataSource = dataSource
            it.jpaVendorAdapter = jpaAdapter


            it.jpaPropertyMap = mutableMapOf<String, Any?>(
                "eclipselink.weaving" to "false",
                "eclipselink.logging.level" to "INFO",
                "eclipselink.logging.level.sql" to "INFO",
                "eclipselink.cache.shared.default" to "false",
            )
        }
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
                        ),
                        StandardCharsets.UTF_8
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
        return EclipseLinkJpaVendorAdapter().apply {
            setDatabase(Database.HSQL)
            setShowSql(true)
        }
    }

    @Bean
    fun transactionManager(): PlatformTransactionManager {
        val platformTransactionManager = JpaTransactionManager()
        platformTransactionManager.entityManagerFactory = entityManagerFactory
        return platformTransactionManager
    }
}
