// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class MonitoredResourceAliasesCredentialArgs extends com.pulumi.resources.ResourceArgs {

    public static final MonitoredResourceAliasesCredentialArgs Empty = new MonitoredResourceAliasesCredentialArgs();

    /**
     * (Updatable) property name
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return (Updatable) property name
     * 
     */
    public Output<String> name() {
        return this.name;
    }

    /**
     * (Updatable) The name of the service owning the credential. Ex stack-monitoring or dbmgmt
     * 
     */
    @Import(name="service", required=true)
    private Output<String> service;

    /**
     * @return (Updatable) The name of the service owning the credential. Ex stack-monitoring or dbmgmt
     * 
     */
    public Output<String> service() {
        return this.service;
    }

    /**
     * (Updatable) The source type and source name combination,delimited with (.) separator. {source type}.{source name} and source type max char limit is 63.
     * 
     */
    @Import(name="source", required=true)
    private Output<String> source;

    /**
     * @return (Updatable) The source type and source name combination,delimited with (.) separator. {source type}.{source name} and source type max char limit is 63.
     * 
     */
    public Output<String> source() {
        return this.source;
    }

    private MonitoredResourceAliasesCredentialArgs() {}

    private MonitoredResourceAliasesCredentialArgs(MonitoredResourceAliasesCredentialArgs $) {
        this.name = $.name;
        this.service = $.service;
        this.source = $.source;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MonitoredResourceAliasesCredentialArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MonitoredResourceAliasesCredentialArgs $;

        public Builder() {
            $ = new MonitoredResourceAliasesCredentialArgs();
        }

        public Builder(MonitoredResourceAliasesCredentialArgs defaults) {
            $ = new MonitoredResourceAliasesCredentialArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param name (Updatable) property name
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) property name
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param service (Updatable) The name of the service owning the credential. Ex stack-monitoring or dbmgmt
         * 
         * @return builder
         * 
         */
        public Builder service(Output<String> service) {
            $.service = service;
            return this;
        }

        /**
         * @param service (Updatable) The name of the service owning the credential. Ex stack-monitoring or dbmgmt
         * 
         * @return builder
         * 
         */
        public Builder service(String service) {
            return service(Output.of(service));
        }

        /**
         * @param source (Updatable) The source type and source name combination,delimited with (.) separator. {source type}.{source name} and source type max char limit is 63.
         * 
         * @return builder
         * 
         */
        public Builder source(Output<String> source) {
            $.source = source;
            return this;
        }

        /**
         * @param source (Updatable) The source type and source name combination,delimited with (.) separator. {source type}.{source name} and source type max char limit is 63.
         * 
         * @return builder
         * 
         */
        public Builder source(String source) {
            return source(Output.of(source));
        }

        public MonitoredResourceAliasesCredentialArgs build() {
            $.name = Objects.requireNonNull($.name, "expected parameter 'name' to be non-null");
            $.service = Objects.requireNonNull($.service, "expected parameter 'service' to be non-null");
            $.source = Objects.requireNonNull($.source, "expected parameter 'source' to be non-null");
            return $;
        }
    }

}