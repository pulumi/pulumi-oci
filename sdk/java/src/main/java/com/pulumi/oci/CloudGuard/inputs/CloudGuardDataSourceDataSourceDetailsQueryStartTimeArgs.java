// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CloudGuardDataSourceDataSourceDetailsQueryStartTimeArgs extends com.pulumi.resources.ResourceArgs {

    public static final CloudGuardDataSourceDataSourceDetailsQueryStartTimeArgs Empty = new CloudGuardDataSourceDataSourceDetailsQueryStartTimeArgs();

    /**
     * (Updatable) Time when the query can start. If not specified it can start immediately
     * 
     */
    @Import(name="queryStartTime")
    private @Nullable Output<String> queryStartTime;

    /**
     * @return (Updatable) Time when the query can start. If not specified it can start immediately
     * 
     */
    public Optional<Output<String>> queryStartTime() {
        return Optional.ofNullable(this.queryStartTime);
    }

    /**
     * (Updatable) Start policy delay timing
     * 
     */
    @Import(name="startPolicyType", required=true)
    private Output<String> startPolicyType;

    /**
     * @return (Updatable) Start policy delay timing
     * 
     */
    public Output<String> startPolicyType() {
        return this.startPolicyType;
    }

    private CloudGuardDataSourceDataSourceDetailsQueryStartTimeArgs() {}

    private CloudGuardDataSourceDataSourceDetailsQueryStartTimeArgs(CloudGuardDataSourceDataSourceDetailsQueryStartTimeArgs $) {
        this.queryStartTime = $.queryStartTime;
        this.startPolicyType = $.startPolicyType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CloudGuardDataSourceDataSourceDetailsQueryStartTimeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CloudGuardDataSourceDataSourceDetailsQueryStartTimeArgs $;

        public Builder() {
            $ = new CloudGuardDataSourceDataSourceDetailsQueryStartTimeArgs();
        }

        public Builder(CloudGuardDataSourceDataSourceDetailsQueryStartTimeArgs defaults) {
            $ = new CloudGuardDataSourceDataSourceDetailsQueryStartTimeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param queryStartTime (Updatable) Time when the query can start. If not specified it can start immediately
         * 
         * @return builder
         * 
         */
        public Builder queryStartTime(@Nullable Output<String> queryStartTime) {
            $.queryStartTime = queryStartTime;
            return this;
        }

        /**
         * @param queryStartTime (Updatable) Time when the query can start. If not specified it can start immediately
         * 
         * @return builder
         * 
         */
        public Builder queryStartTime(String queryStartTime) {
            return queryStartTime(Output.of(queryStartTime));
        }

        /**
         * @param startPolicyType (Updatable) Start policy delay timing
         * 
         * @return builder
         * 
         */
        public Builder startPolicyType(Output<String> startPolicyType) {
            $.startPolicyType = startPolicyType;
            return this;
        }

        /**
         * @param startPolicyType (Updatable) Start policy delay timing
         * 
         * @return builder
         * 
         */
        public Builder startPolicyType(String startPolicyType) {
            return startPolicyType(Output.of(startPolicyType));
        }

        public CloudGuardDataSourceDataSourceDetailsQueryStartTimeArgs build() {
            if ($.startPolicyType == null) {
                throw new MissingRequiredPropertyException("CloudGuardDataSourceDataSourceDetailsQueryStartTimeArgs", "startPolicyType");
            }
            return $;
        }
    }

}
