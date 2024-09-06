<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('user_profiles', function (Blueprint $table) {
            $table->id();
            $table->string('username')->unique();
            $table->string('gender')->nullable();
            $table->string('usia')->nullable();
            $table->string('group_id')->nullable();
            $table->string('policy_no')->nullable();
            $table->string('sid')->nullable();
            $table->string('payor')->nullable();
            $table->string('corporate')->nullable();
            $table->text('firebase_token')->nullable();
            $table->string('email')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('user_profiles');
    }
};
