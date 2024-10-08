// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Oda.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class OdaInstanceRestrictedOperationArgs extends com.pulumi.resources.ResourceArgs {

    public static final OdaInstanceRestrictedOperationArgs Empty = new OdaInstanceRestrictedOperationArgs();

    /**
     * Name of the restricted operation.
     * 
     */
    @Import(name="operationName")
    private @Nullable Output<String> operationName;

    /**
     * @return Name of the restricted operation.
     * 
     */
    public Optional<Output<String>> operationName() {
        return Optional.ofNullable(this.operationName);
    }

    /**
     * Name of the service restricting the operation.
     * 
     */
    @Import(name="restrictingService")
    private @Nullable Output<String> restrictingService;

    /**
     * @return Name of the service restricting the operation.
     * 
     */
    public Optional<Output<String>> restrictingService() {
        return Optional.ofNullable(this.restrictingService);
    }

    private OdaInstanceRestrictedOperationArgs() {}

    private OdaInstanceRestrictedOperationArgs(OdaInstanceRestrictedOperationArgs $) {
        this.operationName = $.operationName;
        this.restrictingService = $.restrictingService;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(OdaInstanceRestrictedOperationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private OdaInstanceRestrictedOperationArgs $;

        public Builder() {
            $ = new OdaInstanceRestrictedOperationArgs();
        }

        public Builder(OdaInstanceRestrictedOperationArgs defaults) {
            $ = new OdaInstanceRestrictedOperationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param operationName Name of the restricted operation.
         * 
         * @return builder
         * 
         */
        public Builder operationName(@Nullable Output<String> operationName) {
            $.operationName = operationName;
            return this;
        }

        /**
         * @param operationName Name of the restricted operation.
         * 
         * @return builder
         * 
         */
        public Builder operationName(String operationName) {
            return operationName(Output.of(operationName));
        }

        /**
         * @param restrictingService Name of the service restricting the operation.
         * 
         * @return builder
         * 
         */
        public Builder restrictingService(@Nullable Output<String> restrictingService) {
            $.restrictingService = restrictingService;
            return this;
        }

        /**
         * @param restrictingService Name of the service restricting the operation.
         * 
         * @return builder
         * 
         */
        public Builder restrictingService(String restrictingService) {
            return restrictingService(Output.of(restrictingService));
        }

        public OdaInstanceRestrictedOperationArgs build() {
            return $;
        }
    }

}
