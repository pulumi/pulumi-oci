// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OperatorAccessControl.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetControlAssignmentPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetControlAssignmentPlainArgs Empty = new GetControlAssignmentPlainArgs();

    /**
     * unique OperatorControl identifier
     * 
     */
    @Import(name="operatorControlAssignmentId", required=true)
    private String operatorControlAssignmentId;

    /**
     * @return unique OperatorControl identifier
     * 
     */
    public String operatorControlAssignmentId() {
        return this.operatorControlAssignmentId;
    }

    private GetControlAssignmentPlainArgs() {}

    private GetControlAssignmentPlainArgs(GetControlAssignmentPlainArgs $) {
        this.operatorControlAssignmentId = $.operatorControlAssignmentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetControlAssignmentPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetControlAssignmentPlainArgs $;

        public Builder() {
            $ = new GetControlAssignmentPlainArgs();
        }

        public Builder(GetControlAssignmentPlainArgs defaults) {
            $ = new GetControlAssignmentPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param operatorControlAssignmentId unique OperatorControl identifier
         * 
         * @return builder
         * 
         */
        public Builder operatorControlAssignmentId(String operatorControlAssignmentId) {
            $.operatorControlAssignmentId = operatorControlAssignmentId;
            return this;
        }

        public GetControlAssignmentPlainArgs build() {
            if ($.operatorControlAssignmentId == null) {
                throw new MissingRequiredPropertyException("GetControlAssignmentPlainArgs", "operatorControlAssignmentId");
            }
            return $;
        }
    }

}
