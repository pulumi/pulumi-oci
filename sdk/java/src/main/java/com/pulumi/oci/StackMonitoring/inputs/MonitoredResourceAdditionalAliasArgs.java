// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.StackMonitoring.inputs.MonitoredResourceAdditionalAliasCredentialArgs;
import java.lang.String;
import java.util.Objects;


public final class MonitoredResourceAdditionalAliasArgs extends com.pulumi.resources.ResourceArgs {

    public static final MonitoredResourceAdditionalAliasArgs Empty = new MonitoredResourceAdditionalAliasArgs();

    /**
     * (Updatable) Monitored Resource Alias Reference Source Credential.
     * 
     */
    @Import(name="credential", required=true)
    private Output<MonitoredResourceAdditionalAliasCredentialArgs> credential;

    /**
     * @return (Updatable) Monitored Resource Alias Reference Source Credential.
     * 
     */
    public Output<MonitoredResourceAdditionalAliasCredentialArgs> credential() {
        return this.credential;
    }

    /**
     * (Updatable) The name of the alias, within the context of the source.
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return (Updatable) The name of the alias, within the context of the source.
     * 
     */
    public Output<String> name() {
        return this.name;
    }

    /**
     * (Updatable) The source type and source name combination,delimited with (.) separator. Example: {source type}.{source name} and source type max char limit is 63.
     * 
     */
    @Import(name="source", required=true)
    private Output<String> source;

    /**
     * @return (Updatable) The source type and source name combination,delimited with (.) separator. Example: {source type}.{source name} and source type max char limit is 63.
     * 
     */
    public Output<String> source() {
        return this.source;
    }

    private MonitoredResourceAdditionalAliasArgs() {}

    private MonitoredResourceAdditionalAliasArgs(MonitoredResourceAdditionalAliasArgs $) {
        this.credential = $.credential;
        this.name = $.name;
        this.source = $.source;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MonitoredResourceAdditionalAliasArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MonitoredResourceAdditionalAliasArgs $;

        public Builder() {
            $ = new MonitoredResourceAdditionalAliasArgs();
        }

        public Builder(MonitoredResourceAdditionalAliasArgs defaults) {
            $ = new MonitoredResourceAdditionalAliasArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param credential (Updatable) Monitored Resource Alias Reference Source Credential.
         * 
         * @return builder
         * 
         */
        public Builder credential(Output<MonitoredResourceAdditionalAliasCredentialArgs> credential) {
            $.credential = credential;
            return this;
        }

        /**
         * @param credential (Updatable) Monitored Resource Alias Reference Source Credential.
         * 
         * @return builder
         * 
         */
        public Builder credential(MonitoredResourceAdditionalAliasCredentialArgs credential) {
            return credential(Output.of(credential));
        }

        /**
         * @param name (Updatable) The name of the alias, within the context of the source.
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) The name of the alias, within the context of the source.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param source (Updatable) The source type and source name combination,delimited with (.) separator. Example: {source type}.{source name} and source type max char limit is 63.
         * 
         * @return builder
         * 
         */
        public Builder source(Output<String> source) {
            $.source = source;
            return this;
        }

        /**
         * @param source (Updatable) The source type and source name combination,delimited with (.) separator. Example: {source type}.{source name} and source type max char limit is 63.
         * 
         * @return builder
         * 
         */
        public Builder source(String source) {
            return source(Output.of(source));
        }

        public MonitoredResourceAdditionalAliasArgs build() {
            if ($.credential == null) {
                throw new MissingRequiredPropertyException("MonitoredResourceAdditionalAliasArgs", "credential");
            }
            if ($.name == null) {
                throw new MissingRequiredPropertyException("MonitoredResourceAdditionalAliasArgs", "name");
            }
            if ($.source == null) {
                throw new MissingRequiredPropertyException("MonitoredResourceAdditionalAliasArgs", "source");
            }
            return $;
        }
    }

}
