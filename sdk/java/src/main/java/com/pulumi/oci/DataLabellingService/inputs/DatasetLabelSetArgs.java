// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataLabellingService.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataLabellingService.inputs.DatasetLabelSetItemArgs;
import java.util.List;
import java.util.Objects;


public final class DatasetLabelSetArgs extends com.pulumi.resources.ResourceArgs {

    public static final DatasetLabelSetArgs Empty = new DatasetLabelSetArgs();

    /**
     * An ordered collection of labels that are unique by name.
     * 
     */
    @Import(name="items", required=true)
    private Output<List<DatasetLabelSetItemArgs>> items;

    /**
     * @return An ordered collection of labels that are unique by name.
     * 
     */
    public Output<List<DatasetLabelSetItemArgs>> items() {
        return this.items;
    }

    private DatasetLabelSetArgs() {}

    private DatasetLabelSetArgs(DatasetLabelSetArgs $) {
        this.items = $.items;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DatasetLabelSetArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DatasetLabelSetArgs $;

        public Builder() {
            $ = new DatasetLabelSetArgs();
        }

        public Builder(DatasetLabelSetArgs defaults) {
            $ = new DatasetLabelSetArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param items An ordered collection of labels that are unique by name.
         * 
         * @return builder
         * 
         */
        public Builder items(Output<List<DatasetLabelSetItemArgs>> items) {
            $.items = items;
            return this;
        }

        /**
         * @param items An ordered collection of labels that are unique by name.
         * 
         * @return builder
         * 
         */
        public Builder items(List<DatasetLabelSetItemArgs> items) {
            return items(Output.of(items));
        }

        /**
         * @param items An ordered collection of labels that are unique by name.
         * 
         * @return builder
         * 
         */
        public Builder items(DatasetLabelSetItemArgs... items) {
            return items(List.of(items));
        }

        public DatasetLabelSetArgs build() {
            if ($.items == null) {
                throw new MissingRequiredPropertyException("DatasetLabelSetArgs", "items");
            }
            return $;
        }
    }

}
