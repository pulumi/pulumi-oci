// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetGuardTargetPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetGuardTargetPlainArgs Empty = new GetGuardTargetPlainArgs();

    /**
     * OCID of the target
     * 
     */
    @Import(name="targetId", required=true)
    private String targetId;

    /**
     * @return OCID of the target
     * 
     */
    public String targetId() {
        return this.targetId;
    }

    private GetGuardTargetPlainArgs() {}

    private GetGuardTargetPlainArgs(GetGuardTargetPlainArgs $) {
        this.targetId = $.targetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetGuardTargetPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetGuardTargetPlainArgs $;

        public Builder() {
            $ = new GetGuardTargetPlainArgs();
        }

        public Builder(GetGuardTargetPlainArgs defaults) {
            $ = new GetGuardTargetPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param targetId OCID of the target
         * 
         * @return builder
         * 
         */
        public Builder targetId(String targetId) {
            $.targetId = targetId;
            return this;
        }

        public GetGuardTargetPlainArgs build() {
            if ($.targetId == null) {
                throw new MissingRequiredPropertyException("GetGuardTargetPlainArgs", "targetId");
            }
            return $;
        }
    }

}
