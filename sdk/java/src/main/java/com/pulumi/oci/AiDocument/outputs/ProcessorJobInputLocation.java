// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiDocument.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.AiDocument.outputs.ProcessorJobInputLocationObjectLocation;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ProcessorJobInputLocation {
    /**
     * @return Raw document data with Base64 encoding.
     * 
     */
    private @Nullable String data;
    /**
     * @return The list of ObjectLocations.
     * 
     */
    private @Nullable List<ProcessorJobInputLocationObjectLocation> objectLocations;
    /**
     * @return The type of input location. The allowed values are:
     * 
     */
    private String sourceType;

    private ProcessorJobInputLocation() {}
    /**
     * @return Raw document data with Base64 encoding.
     * 
     */
    public Optional<String> data() {
        return Optional.ofNullable(this.data);
    }
    /**
     * @return The list of ObjectLocations.
     * 
     */
    public List<ProcessorJobInputLocationObjectLocation> objectLocations() {
        return this.objectLocations == null ? List.of() : this.objectLocations;
    }
    /**
     * @return The type of input location. The allowed values are:
     * 
     */
    public String sourceType() {
        return this.sourceType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ProcessorJobInputLocation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String data;
        private @Nullable List<ProcessorJobInputLocationObjectLocation> objectLocations;
        private String sourceType;
        public Builder() {}
        public Builder(ProcessorJobInputLocation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.data = defaults.data;
    	      this.objectLocations = defaults.objectLocations;
    	      this.sourceType = defaults.sourceType;
        }

        @CustomType.Setter
        public Builder data(@Nullable String data) {
            this.data = data;
            return this;
        }
        @CustomType.Setter
        public Builder objectLocations(@Nullable List<ProcessorJobInputLocationObjectLocation> objectLocations) {
            this.objectLocations = objectLocations;
            return this;
        }
        public Builder objectLocations(ProcessorJobInputLocationObjectLocation... objectLocations) {
            return objectLocations(List.of(objectLocations));
        }
        @CustomType.Setter
        public Builder sourceType(String sourceType) {
            this.sourceType = Objects.requireNonNull(sourceType);
            return this;
        }
        public ProcessorJobInputLocation build() {
            final var o = new ProcessorJobInputLocation();
            o.data = data;
            o.objectLocations = objectLocations;
            o.sourceType = sourceType;
            return o;
        }
    }
}