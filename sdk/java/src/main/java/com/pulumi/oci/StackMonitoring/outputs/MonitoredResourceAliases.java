// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.StackMonitoring.outputs.MonitoredResourceAliasesCredential;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class MonitoredResourceAliases {
    /**
     * @return (Updatable) Monitored Resource Alias Reference Source Credential
     * 
     */
    private final MonitoredResourceAliasesCredential credential;
    /**
     * @return (Updatable) property name
     * 
     */
    private final String name;
    /**
     * @return (Updatable) The source type and source name combination,delimited with (.) separator. {source type}.{source name} and source type max char limit is 63.
     * 
     */
    private final String source;

    @CustomType.Constructor
    private MonitoredResourceAliases(
        @CustomType.Parameter("credential") MonitoredResourceAliasesCredential credential,
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("source") String source) {
        this.credential = credential;
        this.name = name;
        this.source = source;
    }

    /**
     * @return (Updatable) Monitored Resource Alias Reference Source Credential
     * 
     */
    public MonitoredResourceAliasesCredential credential() {
        return this.credential;
    }
    /**
     * @return (Updatable) property name
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return (Updatable) The source type and source name combination,delimited with (.) separator. {source type}.{source name} and source type max char limit is 63.
     * 
     */
    public String source() {
        return this.source;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MonitoredResourceAliases defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MonitoredResourceAliasesCredential credential;
        private String name;
        private String source;

        public Builder() {
    	      // Empty
        }

        public Builder(MonitoredResourceAliases defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.credential = defaults.credential;
    	      this.name = defaults.name;
    	      this.source = defaults.source;
        }

        public Builder credential(MonitoredResourceAliasesCredential credential) {
            this.credential = Objects.requireNonNull(credential);
            return this;
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder source(String source) {
            this.source = Objects.requireNonNull(source);
            return this;
        }        public MonitoredResourceAliases build() {
            return new MonitoredResourceAliases(credential, name, source);
        }
    }
}
