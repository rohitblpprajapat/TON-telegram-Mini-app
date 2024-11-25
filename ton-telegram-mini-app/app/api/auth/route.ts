import { encrypt, SESSION_DURATION } from "@/utils/session"
import { validateTelgramWebAppData } from "@/utils/telegramAuth"
import { NextResponse } from "next/server"
import { cookies } from "next/headers"

export async function POST(request:Request) {
    const { initData } = await request.json()

    const ValidationResult = validateTelgramWebAppData(initData)

    if (ValidationResult.validatedData){
        console.log("Validation result: ", ValidationResult)
        const user = { telegramId: ValidationResult.user.id}


        //create new session

        const expires = new Date(Date.now() + SESSION_DURATION)
        const session = await encrypt({user, expires})

        // Save the session in a cookie
        const cookieStore = await cookies()
        cookieStore.set("session", session, {expires, httpOnly: true})
    }else{
        return NextResponse.json({ message: ValidationResult.message}, { status: 401})

    }
}