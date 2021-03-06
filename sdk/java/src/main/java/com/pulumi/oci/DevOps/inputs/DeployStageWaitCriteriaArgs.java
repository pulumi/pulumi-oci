// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class DeployStageWaitCriteriaArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeployStageWaitCriteriaArgs Empty = new DeployStageWaitCriteriaArgs();

    /**
     * (Updatable) The absolute wait duration. An ISO 8601 formatted duration string. Minimum waitDuration should be 5 seconds. Maximum waitDuration can be up to 2 days.
     * 
     */
    @Import(name="waitDuration", required=true)
    private Output<String> waitDuration;

    /**
     * @return (Updatable) The absolute wait duration. An ISO 8601 formatted duration string. Minimum waitDuration should be 5 seconds. Maximum waitDuration can be up to 2 days.
     * 
     */
    public Output<String> waitDuration() {
        return this.waitDuration;
    }

    /**
     * (Updatable) Wait criteria type.
     * 
     */
    @Import(name="waitType", required=true)
    private Output<String> waitType;

    /**
     * @return (Updatable) Wait criteria type.
     * 
     */
    public Output<String> waitType() {
        return this.waitType;
    }

    private DeployStageWaitCriteriaArgs() {}

    private DeployStageWaitCriteriaArgs(DeployStageWaitCriteriaArgs $) {
        this.waitDuration = $.waitDuration;
        this.waitType = $.waitType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeployStageWaitCriteriaArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeployStageWaitCriteriaArgs $;

        public Builder() {
            $ = new DeployStageWaitCriteriaArgs();
        }

        public Builder(DeployStageWaitCriteriaArgs defaults) {
            $ = new DeployStageWaitCriteriaArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param waitDuration (Updatable) The absolute wait duration. An ISO 8601 formatted duration string. Minimum waitDuration should be 5 seconds. Maximum waitDuration can be up to 2 days.
         * 
         * @return builder
         * 
         */
        public Builder waitDuration(Output<String> waitDuration) {
            $.waitDuration = waitDuration;
            return this;
        }

        /**
         * @param waitDuration (Updatable) The absolute wait duration. An ISO 8601 formatted duration string. Minimum waitDuration should be 5 seconds. Maximum waitDuration can be up to 2 days.
         * 
         * @return builder
         * 
         */
        public Builder waitDuration(String waitDuration) {
            return waitDuration(Output.of(waitDuration));
        }

        /**
         * @param waitType (Updatable) Wait criteria type.
         * 
         * @return builder
         * 
         */
        public Builder waitType(Output<String> waitType) {
            $.waitType = waitType;
            return this;
        }

        /**
         * @param waitType (Updatable) Wait criteria type.
         * 
         * @return builder
         * 
         */
        public Builder waitType(String waitType) {
            return waitType(Output.of(waitType));
        }

        public DeployStageWaitCriteriaArgs build() {
            $.waitDuration = Objects.requireNonNull($.waitDuration, "expected parameter 'waitDuration' to be non-null");
            $.waitType = Objects.requireNonNull($.waitType, "expected parameter 'waitType' to be non-null");
            return $;
        }
    }

}
