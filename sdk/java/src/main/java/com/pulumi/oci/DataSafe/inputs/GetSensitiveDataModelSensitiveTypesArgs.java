// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.inputs.GetSensitiveDataModelSensitiveTypesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSensitiveDataModelSensitiveTypesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSensitiveDataModelSensitiveTypesArgs Empty = new GetSensitiveDataModelSensitiveTypesArgs();

    @Import(name="filters")
    private @Nullable Output<List<GetSensitiveDataModelSensitiveTypesFilterArgs>> filters;

    public Optional<Output<List<GetSensitiveDataModelSensitiveTypesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The OCID of the sensitive data model.
     * 
     */
    @Import(name="sensitiveDataModelId", required=true)
    private Output<String> sensitiveDataModelId;

    /**
     * @return The OCID of the sensitive data model.
     * 
     */
    public Output<String> sensitiveDataModelId() {
        return this.sensitiveDataModelId;
    }

    /**
     * A filter to return only items related to a specific sensitive type OCID.
     * 
     */
    @Import(name="sensitiveTypeId")
    private @Nullable Output<String> sensitiveTypeId;

    /**
     * @return A filter to return only items related to a specific sensitive type OCID.
     * 
     */
    public Optional<Output<String>> sensitiveTypeId() {
        return Optional.ofNullable(this.sensitiveTypeId);
    }

    private GetSensitiveDataModelSensitiveTypesArgs() {}

    private GetSensitiveDataModelSensitiveTypesArgs(GetSensitiveDataModelSensitiveTypesArgs $) {
        this.filters = $.filters;
        this.sensitiveDataModelId = $.sensitiveDataModelId;
        this.sensitiveTypeId = $.sensitiveTypeId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSensitiveDataModelSensitiveTypesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSensitiveDataModelSensitiveTypesArgs $;

        public Builder() {
            $ = new GetSensitiveDataModelSensitiveTypesArgs();
        }

        public Builder(GetSensitiveDataModelSensitiveTypesArgs defaults) {
            $ = new GetSensitiveDataModelSensitiveTypesArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable Output<List<GetSensitiveDataModelSensitiveTypesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetSensitiveDataModelSensitiveTypesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetSensitiveDataModelSensitiveTypesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param sensitiveDataModelId The OCID of the sensitive data model.
         * 
         * @return builder
         * 
         */
        public Builder sensitiveDataModelId(Output<String> sensitiveDataModelId) {
            $.sensitiveDataModelId = sensitiveDataModelId;
            return this;
        }

        /**
         * @param sensitiveDataModelId The OCID of the sensitive data model.
         * 
         * @return builder
         * 
         */
        public Builder sensitiveDataModelId(String sensitiveDataModelId) {
            return sensitiveDataModelId(Output.of(sensitiveDataModelId));
        }

        /**
         * @param sensitiveTypeId A filter to return only items related to a specific sensitive type OCID.
         * 
         * @return builder
         * 
         */
        public Builder sensitiveTypeId(@Nullable Output<String> sensitiveTypeId) {
            $.sensitiveTypeId = sensitiveTypeId;
            return this;
        }

        /**
         * @param sensitiveTypeId A filter to return only items related to a specific sensitive type OCID.
         * 
         * @return builder
         * 
         */
        public Builder sensitiveTypeId(String sensitiveTypeId) {
            return sensitiveTypeId(Output.of(sensitiveTypeId));
        }

        public GetSensitiveDataModelSensitiveTypesArgs build() {
            if ($.sensitiveDataModelId == null) {
                throw new MissingRequiredPropertyException("GetSensitiveDataModelSensitiveTypesArgs", "sensitiveDataModelId");
            }
            return $;
        }
    }

}
