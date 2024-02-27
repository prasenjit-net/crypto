/*
 *    Copyright 2023 Prasenjit Purohit
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
plugins {
    `java-library`
    `maven-publish`
    signing
    `project-report`
    id("net.researchgate.release") version "3.0.2"
    id("io.github.gradle-nexus.publish-plugin") version "2.0.0-rc-2"
}

val cryptoVersion: String? by project
println(cryptoVersion)

description = "A Cryptographic Operation Utility Library"
group = "io.github.prasenjit-net"
version = cryptoVersion!!

java.sourceCompatibility = JavaVersion.VERSION_1_8

dependencies {
    val slf4jVersion: String? by project
    val junitVersion: String? by project
    api("org.slf4j:slf4j-api:${slf4jVersion}")
    testImplementation(platform("org.junit:junit-bom:${junitVersion}"))
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testImplementation("org.junit.jupiter:junit-jupiter-engine")
    testImplementation("ch.qos.logback:logback-core:1.4.12")
}

java {
    withJavadocJar()
    withSourcesJar()
}

tasks.jar {
    manifest {
        attributes(
                mapOf(
                        "Implementation-Title" to project.name,
                        "Implementation-Version" to project.version,
                        "Description" to project.description
                )
        )
    }
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}

repositories {
    mavenCentral()
}

release {
    git {
        requireBranch = "master"
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            pom {
                name.set("Crypto")
                description.set("A easy to use cryptography library implementing common use cases for enterprise security requirements.")
                url.set("https://www.prasenjit.net/crypto/")
                licenses {
                    licenses {
                        name.set("The Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        name.set("Prasenjit Purohit")
                        email.set("prasenjit@prasenjit.net")
                        organization.set("Prasenjit.net")
                        organizationUrl.set("https://www.prasenjit.net")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/prasenjit-net/crypto.git")
                    developerConnection.set("scm:git:https://github.com/prasenjit-net/crypto.git")
                    url.set("https://github.com/prasenjit-net/crypto")
                    tag.set("HEAD")
                }
            }
        }
    }

    repositories {
        maven {
            val repoUsername: String? by project
            val repoPassword: String? by project
            name = "OSSRH"
            val snapshotRepo = "https://oss.sonatype.org/content/repositories/snapshots/"
            val releaseRepo = "https://oss.sonatype.org/service/local/staging/deploy/maven2/"
            url = uri(if (version.toString().endsWith("SNAPSHOT")) snapshotRepo else releaseRepo)
            credentials {
                username = repoUsername
                password = repoPassword
            }
        }
    }
}

signing {
    if (System.getenv("CI") != null) {
        useGpgCmd()
    }
    sign(publishing.publications)
}