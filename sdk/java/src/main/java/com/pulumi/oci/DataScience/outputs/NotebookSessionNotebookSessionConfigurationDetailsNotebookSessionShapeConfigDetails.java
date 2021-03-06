// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Double;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class NotebookSessionNotebookSessionConfigurationDetailsNotebookSessionShapeConfigDetails {
    /**
     * @return (Updatable) A notebook session instance of type VM.Standard.E3.Flex allows memory to be specified. This specifies the size of the memory in GBs.
     * 
     */
    private final @Nullable Double memoryInGbs;
    /**
     * @return (Updatable) A notebook session instance of type VM.Standard.E3.Flex allows the ocpu count to be specified.
     * 
     */
    private final @Nullable Double ocpus;

    @CustomType.Constructor
    private NotebookSessionNotebookSessionConfigurationDetailsNotebookSessionShapeConfigDetails(
        @CustomType.Parameter("memoryInGbs") @Nullable Double memoryInGbs,
        @CustomType.Parameter("ocpus") @Nullable Double ocpus) {
        this.memoryInGbs = memoryInGbs;
        this.ocpus = ocpus;
    }

    /**
     * @return (Updatable) A notebook session instance of type VM.Standard.E3.Flex allows memory to be specified. This specifies the size of the memory in GBs.
     * 
     */
    public Optional<Double> memoryInGbs() {
        return Optional.ofNullable(this.memoryInGbs);
    }
    /**
     * @return (Updatable) A notebook session instance of type VM.Standard.E3.Flex allows the ocpu count to be specified.
     * 
     */
    public Optional<Double> ocpus() {
        return Optional.ofNullable(this.ocpus);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(NotebookSessionNotebookSessionConfigurationDetailsNotebookSessionShapeConfigDetails defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable Double memoryInGbs;
        private @Nullable Double ocpus;

        public Builder() {
    	      // Empty
        }

        public Builder(NotebookSessionNotebookSessionConfigurationDetailsNotebookSessionShapeConfigDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.memoryInGbs = defaults.memoryInGbs;
    	      this.ocpus = defaults.ocpus;
        }

        public Builder memoryInGbs(@Nullable Double memoryInGbs) {
            this.memoryInGbs = memoryInGbs;
            return this;
        }
        public Builder ocpus(@Nullable Double ocpus) {
            this.ocpus = ocpus;
            return this;
        }        public NotebookSessionNotebookSessionConfigurationDetailsNotebookSessionShapeConfigDetails build() {
            return new NotebookSessionNotebookSessionConfigurationDetailsNotebookSessionShapeConfigDetails(memoryInGbs, ocpus);
        }
    }
}
