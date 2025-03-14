// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class MonitoredResourceAliasesCredentialArgs extends com.pulumi.resources.ResourceArgs {

    public static final MonitoredResourceAliasesCredentialArgs Empty = new MonitoredResourceAliasesCredentialArgs();

    /**
     * (Updatable) The name of the pre-existing source credential which alias cred should point to. This should refer to the pre-existing source attribute which is bound to credential name.
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return (Updatable) The name of the pre-existing source credential which alias cred should point to. This should refer to the pre-existing source attribute which is bound to credential name.
     * 
     */
    public Output<String> name() {
        return this.name;
    }

    /**
     * (Updatable) The name of the service owning the credential.  Example: stack-monitoring or dbmgmt
     * 
     */
    @Import(name="service", required=true)
    private Output<String> service;

    /**
     * @return (Updatable) The name of the service owning the credential.  Example: stack-monitoring or dbmgmt
     * 
     */
    public Output<String> service() {
        return this.service;
    }

    /**
     * (Updatable) The source type and source name combination,delimited with (.) separator. This refers to the pre-existing source which alias cred should point to. Ex. {source type}.{source name} and source type max char limit is 63.
     * 
     */
    @Import(name="source", required=true)
    private Output<String> source;

    /**
     * @return (Updatable) The source type and source name combination,delimited with (.) separator. This refers to the pre-existing source which alias cred should point to. Ex. {source type}.{source name} and source type max char limit is 63.
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
         * @param name (Updatable) The name of the pre-existing source credential which alias cred should point to. This should refer to the pre-existing source attribute which is bound to credential name.
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) The name of the pre-existing source credential which alias cred should point to. This should refer to the pre-existing source attribute which is bound to credential name.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param service (Updatable) The name of the service owning the credential.  Example: stack-monitoring or dbmgmt
         * 
         * @return builder
         * 
         */
        public Builder service(Output<String> service) {
            $.service = service;
            return this;
        }

        /**
         * @param service (Updatable) The name of the service owning the credential.  Example: stack-monitoring or dbmgmt
         * 
         * @return builder
         * 
         */
        public Builder service(String service) {
            return service(Output.of(service));
        }

        /**
         * @param source (Updatable) The source type and source name combination,delimited with (.) separator. This refers to the pre-existing source which alias cred should point to. Ex. {source type}.{source name} and source type max char limit is 63.
         * 
         * @return builder
         * 
         */
        public Builder source(Output<String> source) {
            $.source = source;
            return this;
        }

        /**
         * @param source (Updatable) The source type and source name combination,delimited with (.) separator. This refers to the pre-existing source which alias cred should point to. Ex. {source type}.{source name} and source type max char limit is 63.
         * 
         * @return builder
         * 
         */
        public Builder source(String source) {
            return source(Output.of(source));
        }

        public MonitoredResourceAliasesCredentialArgs build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("MonitoredResourceAliasesCredentialArgs", "name");
            }
            if ($.service == null) {
                throw new MissingRequiredPropertyException("MonitoredResourceAliasesCredentialArgs", "service");
            }
            if ($.source == null) {
                throw new MissingRequiredPropertyException("MonitoredResourceAliasesCredentialArgs", "source");
            }
            return $;
        }
    }

}
