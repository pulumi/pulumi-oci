// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.StackMonitoring.outputs.GetMonitoredResourceAliasCredential;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetMonitoredResourceAlias {
    /**
     * @return Monitored Resource Alias Reference Source Credential
     * 
     */
    private List<GetMonitoredResourceAliasCredential> credentials;
    /**
     * @return property name
     * 
     */
    private String name;
    /**
     * @return The source type and source name combination,delimited with (.) separator. {source type}.{source name} and source type max char limit is 63.
     * 
     */
    private String source;

    private GetMonitoredResourceAlias() {}
    /**
     * @return Monitored Resource Alias Reference Source Credential
     * 
     */
    public List<GetMonitoredResourceAliasCredential> credentials() {
        return this.credentials;
    }
    /**
     * @return property name
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The source type and source name combination,delimited with (.) separator. {source type}.{source name} and source type max char limit is 63.
     * 
     */
    public String source() {
        return this.source;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMonitoredResourceAlias defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetMonitoredResourceAliasCredential> credentials;
        private String name;
        private String source;
        public Builder() {}
        public Builder(GetMonitoredResourceAlias defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.credentials = defaults.credentials;
    	      this.name = defaults.name;
    	      this.source = defaults.source;
        }

        @CustomType.Setter
        public Builder credentials(List<GetMonitoredResourceAliasCredential> credentials) {
            this.credentials = Objects.requireNonNull(credentials);
            return this;
        }
        public Builder credentials(GetMonitoredResourceAliasCredential... credentials) {
            return credentials(List.of(credentials));
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder source(String source) {
            this.source = Objects.requireNonNull(source);
            return this;
        }
        public GetMonitoredResourceAlias build() {
            final var o = new GetMonitoredResourceAlias();
            o.credentials = credentials;
            o.name = name;
            o.source = source;
            return o;
        }
    }
}