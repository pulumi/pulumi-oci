// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ConfigDynamicGroupArgs extends com.pulumi.resources.ResourceArgs {

    public static final ConfigDynamicGroupArgs Empty = new ConfigDynamicGroupArgs();

    /**
     * (Updatable) Identity domain name
     * 
     */
    @Import(name="domain")
    private @Nullable Output<String> domain;

    /**
     * @return (Updatable) Identity domain name
     * 
     */
    public Optional<Output<String>> domain() {
        return Optional.ofNullable(this.domain);
    }

    /**
     * (Updatable) Name of dynamic Group
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) Name of dynamic Group
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) Assignment of dynamic group in context of Stack Monitoring service. It describes the purpose of dynamic groups in Stack Monitoring.
     * 
     */
    @Import(name="stackMonitoringAssignment")
    private @Nullable Output<String> stackMonitoringAssignment;

    /**
     * @return (Updatable) Assignment of dynamic group in context of Stack Monitoring service. It describes the purpose of dynamic groups in Stack Monitoring.
     * 
     */
    public Optional<Output<String>> stackMonitoringAssignment() {
        return Optional.ofNullable(this.stackMonitoringAssignment);
    }

    private ConfigDynamicGroupArgs() {}

    private ConfigDynamicGroupArgs(ConfigDynamicGroupArgs $) {
        this.domain = $.domain;
        this.name = $.name;
        this.stackMonitoringAssignment = $.stackMonitoringAssignment;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ConfigDynamicGroupArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ConfigDynamicGroupArgs $;

        public Builder() {
            $ = new ConfigDynamicGroupArgs();
        }

        public Builder(ConfigDynamicGroupArgs defaults) {
            $ = new ConfigDynamicGroupArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param domain (Updatable) Identity domain name
         * 
         * @return builder
         * 
         */
        public Builder domain(@Nullable Output<String> domain) {
            $.domain = domain;
            return this;
        }

        /**
         * @param domain (Updatable) Identity domain name
         * 
         * @return builder
         * 
         */
        public Builder domain(String domain) {
            return domain(Output.of(domain));
        }

        /**
         * @param name (Updatable) Name of dynamic Group
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) Name of dynamic Group
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param stackMonitoringAssignment (Updatable) Assignment of dynamic group in context of Stack Monitoring service. It describes the purpose of dynamic groups in Stack Monitoring.
         * 
         * @return builder
         * 
         */
        public Builder stackMonitoringAssignment(@Nullable Output<String> stackMonitoringAssignment) {
            $.stackMonitoringAssignment = stackMonitoringAssignment;
            return this;
        }

        /**
         * @param stackMonitoringAssignment (Updatable) Assignment of dynamic group in context of Stack Monitoring service. It describes the purpose of dynamic groups in Stack Monitoring.
         * 
         * @return builder
         * 
         */
        public Builder stackMonitoringAssignment(String stackMonitoringAssignment) {
            return stackMonitoringAssignment(Output.of(stackMonitoringAssignment));
        }

        public ConfigDynamicGroupArgs build() {
            return $;
        }
    }

}
