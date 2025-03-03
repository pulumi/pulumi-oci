// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetSensitiveDataModelReferentialRelationArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSensitiveDataModelReferentialRelationArgs Empty = new GetSensitiveDataModelReferentialRelationArgs();

    /**
     * The unique key that identifies the referential relation. It&#39;s numeric and unique within a sensitive data model.
     * 
     */
    @Import(name="key", required=true)
    private Output<String> key;

    /**
     * @return The unique key that identifies the referential relation. It&#39;s numeric and unique within a sensitive data model.
     * 
     */
    public Output<String> key() {
        return this.key;
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

    private GetSensitiveDataModelReferentialRelationArgs() {}

    private GetSensitiveDataModelReferentialRelationArgs(GetSensitiveDataModelReferentialRelationArgs $) {
        this.key = $.key;
        this.sensitiveDataModelId = $.sensitiveDataModelId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSensitiveDataModelReferentialRelationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSensitiveDataModelReferentialRelationArgs $;

        public Builder() {
            $ = new GetSensitiveDataModelReferentialRelationArgs();
        }

        public Builder(GetSensitiveDataModelReferentialRelationArgs defaults) {
            $ = new GetSensitiveDataModelReferentialRelationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param key The unique key that identifies the referential relation. It&#39;s numeric and unique within a sensitive data model.
         * 
         * @return builder
         * 
         */
        public Builder key(Output<String> key) {
            $.key = key;
            return this;
        }

        /**
         * @param key The unique key that identifies the referential relation. It&#39;s numeric and unique within a sensitive data model.
         * 
         * @return builder
         * 
         */
        public Builder key(String key) {
            return key(Output.of(key));
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

        public GetSensitiveDataModelReferentialRelationArgs build() {
            if ($.key == null) {
                throw new MissingRequiredPropertyException("GetSensitiveDataModelReferentialRelationArgs", "key");
            }
            if ($.sensitiveDataModelId == null) {
                throw new MissingRequiredPropertyException("GetSensitiveDataModelReferentialRelationArgs", "sensitiveDataModelId");
            }
            return $;
        }
    }

}
