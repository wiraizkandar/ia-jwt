<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateRefreshTokenTable extends Migration
{
	/**
	 * Run the migrations.
	 *
	 * @return void
	 */
	public function up()
	{
		Schema::create('refresh_tokens', function (Blueprint $table) {
			$table->id();
			$table->string('refresh_token');
			$table->unsignedBigInteger('user_id');
			$table->boolean('revoked')->default(0);
			$table->dateTime('expiry');
			$table->timestamps();
			$table->softDeletes();

			$table->index(['user_id', 'refresh_token'],'usr_rfsh_idx');
		});
	}

	/**
	 * Reverse the migrations.
	 *
	 * @return void
	 */
	public function down()
	{
		Schema::dropIfExists('refresh_tokens');
	}
}