// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveType;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetCompatibleFormatsForSensitiveTypeResult {
    private @Nullable String accessLevel;
    private String compartmentId;
    private @Nullable Boolean compartmentIdInSubtree;
    /**
     * @return An array of library masking formats compatible with the existing sensitive types.
     * 
     */
    private List<GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveType> formatsForSensitiveTypes;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;

    private GetCompatibleFormatsForSensitiveTypeResult() {}
    public Optional<String> accessLevel() {
        return Optional.ofNullable(this.accessLevel);
    }
    public String compartmentId() {
        return this.compartmentId;
    }
    public Optional<Boolean> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }
    /**
     * @return An array of library masking formats compatible with the existing sensitive types.
     * 
     */
    public List<GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveType> formatsForSensitiveTypes() {
        return this.formatsForSensitiveTypes;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCompatibleFormatsForSensitiveTypeResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String accessLevel;
        private String compartmentId;
        private @Nullable Boolean compartmentIdInSubtree;
        private List<GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveType> formatsForSensitiveTypes;
        private String id;
        public Builder() {}
        public Builder(GetCompatibleFormatsForSensitiveTypeResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accessLevel = defaults.accessLevel;
    	      this.compartmentId = defaults.compartmentId;
    	      this.compartmentIdInSubtree = defaults.compartmentIdInSubtree;
    	      this.formatsForSensitiveTypes = defaults.formatsForSensitiveTypes;
    	      this.id = defaults.id;
        }

        @CustomType.Setter
        public Builder accessLevel(@Nullable String accessLevel) {
            this.accessLevel = accessLevel;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentIdInSubtree(@Nullable Boolean compartmentIdInSubtree) {
            this.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }
        @CustomType.Setter
        public Builder formatsForSensitiveTypes(List<GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveType> formatsForSensitiveTypes) {
            this.formatsForSensitiveTypes = Objects.requireNonNull(formatsForSensitiveTypes);
            return this;
        }
        public Builder formatsForSensitiveTypes(GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveType... formatsForSensitiveTypes) {
            return formatsForSensitiveTypes(List.of(formatsForSensitiveTypes));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public GetCompatibleFormatsForSensitiveTypeResult build() {
            final var o = new GetCompatibleFormatsForSensitiveTypeResult();
            o.accessLevel = accessLevel;
            o.compartmentId = compartmentId;
            o.compartmentIdInSubtree = compartmentIdInSubtree;
            o.formatsForSensitiveTypes = formatsForSensitiveTypes;
            o.id = id;
            return o;
        }
    }
}