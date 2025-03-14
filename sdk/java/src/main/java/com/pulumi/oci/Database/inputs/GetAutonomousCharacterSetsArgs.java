// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Database.inputs.GetAutonomousCharacterSetsFilterArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAutonomousCharacterSetsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAutonomousCharacterSetsArgs Empty = new GetAutonomousCharacterSetsArgs();

    /**
     * Specifies whether this request pertains to database character sets or national character sets.
     * 
     */
    @Import(name="characterSetType")
    private @Nullable Output<String> characterSetType;

    /**
     * @return Specifies whether this request pertains to database character sets or national character sets.
     * 
     */
    public Optional<Output<String>> characterSetType() {
        return Optional.ofNullable(this.characterSetType);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetAutonomousCharacterSetsFilterArgs>> filters;

    public Optional<Output<List<GetAutonomousCharacterSetsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Specifies if the request is for an Autonomous Database Dedicated instance. The default request is for an Autonomous Database Dedicated instance.
     * 
     */
    @Import(name="isDedicated")
    private @Nullable Output<Boolean> isDedicated;

    /**
     * @return Specifies if the request is for an Autonomous Database Dedicated instance. The default request is for an Autonomous Database Dedicated instance.
     * 
     */
    public Optional<Output<Boolean>> isDedicated() {
        return Optional.ofNullable(this.isDedicated);
    }

    /**
     * Specifies whether this request is for Autonomous Database on Shared infrastructure. By default, this request will be for Autonomous Database on Dedicated Exadata Infrastructure.
     * 
     * :
     * 
     */
    @Import(name="isShared")
    private @Nullable Output<Boolean> isShared;

    /**
     * @return Specifies whether this request is for Autonomous Database on Shared infrastructure. By default, this request will be for Autonomous Database on Dedicated Exadata Infrastructure.
     * 
     * :
     * 
     */
    public Optional<Output<Boolean>> isShared() {
        return Optional.ofNullable(this.isShared);
    }

    private GetAutonomousCharacterSetsArgs() {}

    private GetAutonomousCharacterSetsArgs(GetAutonomousCharacterSetsArgs $) {
        this.characterSetType = $.characterSetType;
        this.filters = $.filters;
        this.isDedicated = $.isDedicated;
        this.isShared = $.isShared;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAutonomousCharacterSetsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAutonomousCharacterSetsArgs $;

        public Builder() {
            $ = new GetAutonomousCharacterSetsArgs();
        }

        public Builder(GetAutonomousCharacterSetsArgs defaults) {
            $ = new GetAutonomousCharacterSetsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param characterSetType Specifies whether this request pertains to database character sets or national character sets.
         * 
         * @return builder
         * 
         */
        public Builder characterSetType(@Nullable Output<String> characterSetType) {
            $.characterSetType = characterSetType;
            return this;
        }

        /**
         * @param characterSetType Specifies whether this request pertains to database character sets or national character sets.
         * 
         * @return builder
         * 
         */
        public Builder characterSetType(String characterSetType) {
            return characterSetType(Output.of(characterSetType));
        }

        public Builder filters(@Nullable Output<List<GetAutonomousCharacterSetsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetAutonomousCharacterSetsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetAutonomousCharacterSetsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param isDedicated Specifies if the request is for an Autonomous Database Dedicated instance. The default request is for an Autonomous Database Dedicated instance.
         * 
         * @return builder
         * 
         */
        public Builder isDedicated(@Nullable Output<Boolean> isDedicated) {
            $.isDedicated = isDedicated;
            return this;
        }

        /**
         * @param isDedicated Specifies if the request is for an Autonomous Database Dedicated instance. The default request is for an Autonomous Database Dedicated instance.
         * 
         * @return builder
         * 
         */
        public Builder isDedicated(Boolean isDedicated) {
            return isDedicated(Output.of(isDedicated));
        }

        /**
         * @param isShared Specifies whether this request is for Autonomous Database on Shared infrastructure. By default, this request will be for Autonomous Database on Dedicated Exadata Infrastructure.
         * 
         * :
         * 
         * @return builder
         * 
         */
        public Builder isShared(@Nullable Output<Boolean> isShared) {
            $.isShared = isShared;
            return this;
        }

        /**
         * @param isShared Specifies whether this request is for Autonomous Database on Shared infrastructure. By default, this request will be for Autonomous Database on Dedicated Exadata Infrastructure.
         * 
         * :
         * 
         * @return builder
         * 
         */
        public Builder isShared(Boolean isShared) {
            return isShared(Output.of(isShared));
        }

        public GetAutonomousCharacterSetsArgs build() {
            return $;
        }
    }

}
