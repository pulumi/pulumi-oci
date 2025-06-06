// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetModelCustomMetadataArtifactContentPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetModelCustomMetadataArtifactContentPlainArgs Empty = new GetModelCustomMetadataArtifactContentPlainArgs();

    /**
     * The name of the model metadatum in the metadata.
     * 
     */
    @Import(name="metadatumKeyName", required=true)
    private String metadatumKeyName;

    /**
     * @return The name of the model metadatum in the metadata.
     * 
     */
    public String metadatumKeyName() {
        return this.metadatumKeyName;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
     * 
     */
    @Import(name="modelId", required=true)
    private String modelId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
     * 
     */
    public String modelId() {
        return this.modelId;
    }

    /**
     * Optional byte range to fetch, as described in [RFC 7233](https://tools.ietf.org/html/rfc7232#section-2.1), section 2.1. Note that only a single range of bytes is supported.
     * 
     */
    @Import(name="range")
    private @Nullable String range;

    /**
     * @return Optional byte range to fetch, as described in [RFC 7233](https://tools.ietf.org/html/rfc7232#section-2.1), section 2.1. Note that only a single range of bytes is supported.
     * 
     */
    public Optional<String> range() {
        return Optional.ofNullable(this.range);
    }

    private GetModelCustomMetadataArtifactContentPlainArgs() {}

    private GetModelCustomMetadataArtifactContentPlainArgs(GetModelCustomMetadataArtifactContentPlainArgs $) {
        this.metadatumKeyName = $.metadatumKeyName;
        this.modelId = $.modelId;
        this.range = $.range;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetModelCustomMetadataArtifactContentPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetModelCustomMetadataArtifactContentPlainArgs $;

        public Builder() {
            $ = new GetModelCustomMetadataArtifactContentPlainArgs();
        }

        public Builder(GetModelCustomMetadataArtifactContentPlainArgs defaults) {
            $ = new GetModelCustomMetadataArtifactContentPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param metadatumKeyName The name of the model metadatum in the metadata.
         * 
         * @return builder
         * 
         */
        public Builder metadatumKeyName(String metadatumKeyName) {
            $.metadatumKeyName = metadatumKeyName;
            return this;
        }

        /**
         * @param modelId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
         * 
         * @return builder
         * 
         */
        public Builder modelId(String modelId) {
            $.modelId = modelId;
            return this;
        }

        /**
         * @param range Optional byte range to fetch, as described in [RFC 7233](https://tools.ietf.org/html/rfc7232#section-2.1), section 2.1. Note that only a single range of bytes is supported.
         * 
         * @return builder
         * 
         */
        public Builder range(@Nullable String range) {
            $.range = range;
            return this;
        }

        public GetModelCustomMetadataArtifactContentPlainArgs build() {
            if ($.metadatumKeyName == null) {
                throw new MissingRequiredPropertyException("GetModelCustomMetadataArtifactContentPlainArgs", "metadatumKeyName");
            }
            if ($.modelId == null) {
                throw new MissingRequiredPropertyException("GetModelCustomMetadataArtifactContentPlainArgs", "modelId");
            }
            return $;
        }
    }

}
