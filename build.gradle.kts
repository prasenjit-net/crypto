import java.net.URI

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
}

group = "net.prasenjit"
version = "1.5-SNAPSHOT"

java.sourceCompatibility = JavaVersion.VERSION_1_8

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.9.3"))
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testImplementation("org.junit.jupiter:junit-jupiter-engine")
}

java {
//    withJavadocJar()
    withSourcesJar()
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}

repositories {
    mavenCentral()
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
            name = "OSSRH"
            val snapshotRepo = "https://s01.oss.sonatype.org/content/repositories/snapshots/"
            val releaseRepo = "https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/"
            url = uri(if (version.toString().endsWith("SNAPSHOT")) snapshotRepo else releaseRepo)
            credentials {
                username = System.getenv("OSSRH_USERNAME")
                password = System.getenv("OSSRH_TOKEN")
            }
        }
    }
}

signing {
    val signingKeyId: String? by project
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications["maven"])
}